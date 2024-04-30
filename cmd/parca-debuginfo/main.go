// Copyright (c) 2022 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package main

import (
	"archive/tar"
	"context"
	"crypto/tls"
	"debug/dwarf"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/alecthomas/kong"
	"github.com/go-kit/log"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/klauspost/compress/zstd"
	grun "github.com/oklog/run"
	"github.com/parca-dev/parca-agent/pkg/buildid"
	"github.com/parca-dev/parca-agent/pkg/elfwriter"
	debuginfopb "github.com/parca-dev/parca/gen/proto/go/parca/debuginfo/v1alpha1"
	parcadebuginfo "github.com/parca-dev/parca/pkg/debuginfo"
	"github.com/parca-dev/parca/pkg/hash"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rzajac/flexbuf"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	LogLevelDebug = "debug"
)

type flags struct {
	LogLevel string `kong:"enum='error,warn,info,debug',help='Log level.',default='info'"`

	Upload struct {
		StoreAddress       string `kong:"required,help='gRPC address to sends symbols to.'"`
		BearerToken        string `kong:"help='Bearer token to authenticate with store.',env='PARCA_DEBUGINFO_BEARER_TOKEN'"`
		BearerTokenFile    string `kong:"help='File to read bearer token from to authenticate with store.'"`
		Insecure           bool   `kong:"help='Send gRPC requests via plaintext instead of TLS.'"`
		InsecureSkipVerify bool   `kong:"help='Skip TLS certificate verification.'"`
		NoExtract          bool   `kong:"help='Do not extract debug information from binaries, just upload the binary as is.'"`
		NoInitiate         bool   `kong:"help='Do not initiate the upload, just check if it should be initiated.'"`
		Force              bool   `kong:"help='Force upload even if the Build ID is already uploaded.'"`
		Type               string `kong:"enum='debuginfo,executable,sources',help='Type of the debug information to upload.',default='debuginfo'"`
		BuildID            string `kong:"help='Build ID of the binary to upload.'"`

		Paths []string `kong:"required,arg,name='path',help='Paths to upload.',type:'path'"`
	} `cmd:"" help:"Upload debug information files."`

	Extract struct {
		OutputDir string `kong:"help='Output directory path to use for extracted debug information files.',default='out'"`

		Paths                 []string `kong:"required,arg,name='path',help='Paths to extract debug information.',type:'path'"`
		CompressDWARFSections bool     `kong:"default=false,help:'Compress debuginfo files DWARF sections before uploading.'"`
		Mode                  string   `kong:"default='keep-only-debug',enum='keep-only-debug,strip-debug'"`
	} `cmd:"" help:"Extract debug information."`

	Buildid struct {
		Path string `kong:"required,arg,name='path',help='Paths to extract buildid.',type:'path'"`
	} `cmd:"" help:"Extract buildid."`

	Source struct {
		DebuginfoPath string `kong:"required,arg,name='debuginfo-path',help='Path to debuginfo file',type:'path'"`
		OutPath       string `kong:"arg,name='out-path',help='Path to output archive file',type:'path',default='source.tar.zstd'"`
	} `cmd:"" help:"Build a source archive by discovering files from a given debuginfo file."`
}

func main() {
	flags := flags{}
	kongCtx := kong.Parse(&flags)
	if err := run(kongCtx, flags); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type uploadInfo struct {
	buildID string
	path    string
	reader  io.ReadSeeker
	size    int64
}

func run(kongCtx *kong.Context, flags flags) error {
	opts := []elfwriter.Option{}
	if flags.Extract.CompressDWARFSections {
		opts = append(opts, elfwriter.WithCompressDWARFSections())
	}
	extractor := elfwriter.NewExtractor(log.NewNopLogger(), trace.NewNoopTracerProvider().Tracer("noop"), opts...)

	var g grun.Group
	ctx, cancel := context.WithCancel(context.Background())
	switch kongCtx.Command() {
	case "upload <path>":
		g.Add(func() error {
			conn, err := grpcConn(prometheus.NewRegistry(), flags)
			if err != nil {
				return fmt.Errorf("create gRPC connection: %w", err)
			}
			defer conn.Close()

			debuginfoClient := debuginfopb.NewDebuginfoServiceClient(conn)
			grpcUploadClient := parcadebuginfo.NewGrpcUploadClient(debuginfoClient)

			srcDst := map[string]io.WriteSeeker{}
			uploads := []*uploadInfo{}

			if !flags.Upload.NoExtract && flags.Upload.Type == "debuginfo" {
				for _, path := range flags.Upload.Paths {
					ef, err := elf.Open(path)
					if err != nil {
						return fmt.Errorf("open ELF file: %w", err)
					}
					defer ef.Close()

					buildID, err := buildid.FromELF(ef)
					if err != nil {
						return fmt.Errorf("get Build ID for %q: %w", path, err)
					}

					buf := &flexbuf.Buffer{}
					srcDst[path] = buf

					uploads = append(uploads, &uploadInfo{
						buildID: buildID,
						path:    path,
						reader:  buf,
					})
				}

				if len(srcDst) == 0 {
					return errors.New("failed to find actionable files")
				}

				if err := extractAll(ctx, extractor, flags.Extract.Mode, srcDst); err != nil {
					return fmt.Errorf("failed to extract debug information: %w", err)
				}
				for _, upload := range uploads {
					buf, ok := upload.reader.(*flexbuf.Buffer)
					if !ok {
						return fmt.Errorf("failed to cast reader to flexbuf.Buffer, something went terribly wrong as this should be the only type used")
					}

					buf.SeekStart()
					upload.size = int64(buf.Len())

					if upload.size == 0 {
						return fmt.Errorf("extracted debug information from %q is empty, but must not be empty", upload.path)
					}
				}
			} else {
				for _, path := range flags.Upload.Paths {
					buildID := flags.Upload.BuildID

					if flags.Upload.Type == "debuginfo" && buildID == "" {
						ef, err := elf.Open(path)
						if err != nil {
							return fmt.Errorf("open ELF file: %w", err)
						}
						defer ef.Close()

						buildID, err = buildid.FromELF(ef)
						if err != nil {
							return fmt.Errorf("get Build ID for %q: %w", path, err)
						}
					}

					f, err := os.Open(path)
					if err != nil {
						return fmt.Errorf("open file: %w", err)
					}
					defer f.Close()

					fi, err := f.Stat()
					if err != nil {
						return fmt.Errorf("stat file: %w", err)
					}

					if fi.Size() == 0 {
						return fmt.Errorf("file %q is empty, but must not be empty", path)
					}

					uploads = append(uploads, &uploadInfo{
						buildID: buildID,
						path:    path,
						reader:  f,
						size:    fi.Size(),
					})
				}
			}

			for _, upload := range uploads {
				shouldInitiate, err := debuginfoClient.ShouldInitiateUpload(ctx, &debuginfopb.ShouldInitiateUploadRequest{
					BuildId: upload.buildID,
					Force:   flags.Upload.Force,
					Type:    debuginfoTypeStringToPb(flags.Upload.Type),
				})
				if err != nil {
					return fmt.Errorf("check if upload should be initiated for %q with Build ID %q: %w", upload.path, upload.buildID, err)
				}
				if !shouldInitiate.ShouldInitiateUpload {
					fmt.Fprintf(os.Stdout, "Skipping upload of %q with Build ID %q as the store instructed not to: %s\n", upload.path, upload.buildID, shouldInitiate.Reason)
					continue
				}

				if flags.Upload.NoInitiate {
					fmt.Fprintf(os.Stdout, "Not initiating upload of %q with Build ID %q as requested, but would have requested that next, because: %s\n", upload.path, upload.buildID, shouldInitiate.Reason)
					continue
				}

				hash, err := hash.Reader(upload.reader)
				if err != nil {
					return fmt.Errorf("calculate hash of %q with Build ID %q: %w", upload.path, upload.buildID, err)
				}

				if _, err := upload.reader.Seek(0, io.SeekStart); err != nil {
					return fmt.Errorf("seek to start of %q with Build ID %q: %w", upload.path, upload.buildID, err)
				}

				initiationResp, err := debuginfoClient.InitiateUpload(ctx, &debuginfopb.InitiateUploadRequest{
					BuildId: upload.buildID,
					Hash:    hash,
					Size:    upload.size,
					Force:   flags.Upload.Force,
					Type:    debuginfoTypeStringToPb(flags.Upload.Type),
				})
				if err != nil {
					return fmt.Errorf("initiate upload for %q with Build ID %q: %w", upload.path, upload.buildID, err)
				}

				if flags.LogLevel == LogLevelDebug {
					fmt.Fprintf(os.Stdout, "Upload instructions\nBuildID: %s\nUploadID: %s\nUploadStrategy: %s\nSignedURL: %s\nType: %s\n", initiationResp.UploadInstructions.BuildId, initiationResp.UploadInstructions.UploadId, initiationResp.UploadInstructions.UploadStrategy.String(), initiationResp.UploadInstructions.SignedUrl, initiationResp.UploadInstructions.Type)
				}

				switch initiationResp.UploadInstructions.UploadStrategy {
				case debuginfopb.UploadInstructions_UPLOAD_STRATEGY_GRPC:
					if flags.LogLevel == LogLevelDebug {
						fmt.Fprintf(os.Stdout, "Performing a gRPC upload for %q with Build ID %q.", upload.path, upload.buildID)
					}
					_, err = grpcUploadClient.Upload(ctx, initiationResp.UploadInstructions, upload.reader)
				case debuginfopb.UploadInstructions_UPLOAD_STRATEGY_SIGNED_URL:
					if flags.LogLevel == LogLevelDebug {
						fmt.Fprintf(os.Stdout, "Performing a signed URL upload for %q with Build ID %q.", upload.path, upload.buildID)
					}
					err = uploadViaSignedURL(ctx, initiationResp.UploadInstructions.SignedUrl, upload.reader)
				case debuginfopb.UploadInstructions_UPLOAD_STRATEGY_UNSPECIFIED:
					err = errors.New("no upload strategy specified")
				default:
					err = fmt.Errorf("unknown upload strategy: %v", initiationResp.UploadInstructions.UploadStrategy)
				}
				if err != nil {
					return fmt.Errorf("upload %q with Build ID %q: %w", upload.path, upload.buildID, err)
				}

				_, err = debuginfoClient.MarkUploadFinished(ctx, &debuginfopb.MarkUploadFinishedRequest{
					BuildId:  upload.buildID,
					UploadId: initiationResp.UploadInstructions.UploadId,
					Type:     debuginfoTypeStringToPb(flags.Upload.Type),
				})
				if err != nil {
					return fmt.Errorf("mark upload finished for %q with Build ID %q: %w", upload.path, upload.buildID, err)
				}
			}

			return nil
		}, func(error) {
			cancel()
		})

	case "extract <path>":
		g.Add(func() error {
			if err := os.RemoveAll(flags.Extract.OutputDir); err != nil {
				return fmt.Errorf("failed to clean output dir, %s: %w", flags.Extract.OutputDir, err)
			}
			if err := os.MkdirAll(flags.Extract.OutputDir, 0o755); err != nil {
				return fmt.Errorf("failed to create output dir, %s: %w", flags.Extract.OutputDir, err)
			}
			srcDst := map[string]io.WriteSeeker{}
			for _, path := range flags.Extract.Paths {
				ef, err := elf.Open(path)
				if err != nil {
					return fmt.Errorf("open ELF file: %w", err)
				}
				defer ef.Close()

				buildID, err := buildid.FromELF(ef)
				if err != nil {
					return fmt.Errorf("get Build ID for %q: %w", path, err)
				}

				f, err := os.Open(path)
				if err != nil {
					return fmt.Errorf("open file: %w", err)
				}
				defer f.Close()

				// ./out/<buildid>.debuginfo
				output := filepath.Join(flags.Extract.OutputDir, buildID+".debuginfo")

				outFile, err := os.Create(output)
				if err != nil {
					return fmt.Errorf("create output file: %w", err)
				}
				defer outFile.Close()

				srcDst[path] = outFile
			}

			if len(srcDst) == 0 {
				return errors.New("failed to find actionable files")
			}

			return extractAll(ctx, extractor, flags.Extract.Mode, srcDst)
		}, func(error) {
			cancel()
		})

	case "buildid <path>":
		g.Add(func() error {
			ef, err := elf.Open(flags.Buildid.Path)
			if err != nil {
				return fmt.Errorf("open ELF file: %w", err)
			}
			defer ef.Close()

			buildID, err := buildid.FromELF(ef)
			if err != nil {
				return fmt.Errorf("get Build ID for %q: %w", flags.Buildid.Path, err)
			}

			if buildID == "" {
				return errors.New("failed to extract ELF build ID")
			}

			fmt.Fprintf(os.Stdout, "%s", buildID)
			return nil
		}, func(error) {
			cancel()
		})

	case "source <debuginfo-path>":
		g.Add(func() error {
			f, err := elf.Open(flags.Source.DebuginfoPath)
			if err != nil {
				return fmt.Errorf("open elf: %w", err)
			}
			defer f.Close()

			sf, err := os.Create(flags.Source.OutPath)
			if err != nil {
				return fmt.Errorf("create source archive: %w", err)
			}
			defer sf.Close()

			zw, err := zstd.NewWriter(sf)
			if err != nil {
				return fmt.Errorf("create zstd writer: %w", err)
			}

			tw := tar.NewWriter(zw)

			d, err := f.DWARF()
			if err != nil {
				return fmt.Errorf("get dwarf data: %w", err)
			}

			r := d.Reader()
			seen := map[string]struct{}{}
			for {
				e, err := r.Next()
				if err != nil {
					return fmt.Errorf("read DWARF entry: %w", err)
				}
				if e == nil {
					break
				}

				if e.Tag == dwarf.TagCompileUnit {
					lr, err := d.LineReader(e)
					if err != nil {
						return fmt.Errorf("get line reader: %w", err)
					}

					if lr == nil {
						continue
					}

					for _, lineFile := range lr.Files() {
						if lineFile == nil {
							continue
						}
						if _, ok := seen[lineFile.Name]; !ok {
							sourceFile, err := os.Open(lineFile.Name)
							if errors.Is(err, os.ErrNotExist) {
								fmt.Fprintf(os.Stderr, "skipping file %q: does not exist\n", lineFile.Name)
								seen[lineFile.Name] = struct{}{}
								continue
							}
							if err != nil {
								return fmt.Errorf("open file: %w", err)
							}

							stat, err := sourceFile.Stat()
							if err != nil {
								return fmt.Errorf("stat file: %w", err)
							}

							if err := tw.WriteHeader(&tar.Header{
								Name: lineFile.Name,
								Size: stat.Size(),
							}); err != nil {
								return fmt.Errorf("write tar header: %w", err)
							}

							if _, err = io.Copy(tw, sourceFile); err != nil {
								return fmt.Errorf("copy file to tar: %w", err)
							}

							if err := sourceFile.Close(); err != nil {
								return fmt.Errorf("close file: %w", err)
							}

							seen[lineFile.Name] = struct{}{}
						}
					}
				}
			}

			return nil
		}, func(error) {
			cancel()
		})

	default:
		cancel()
		return errors.New("unknown command: " + kongCtx.Command())
	}

	g.Add(grun.SignalHandler(ctx, os.Interrupt, os.Kill))
	return g.Run()
}

// extractAll extracts debug information from the given executables.
// It consumes a map of file sources to extract and a destination io.Writer.
func extractAll(ctx context.Context, e *elfwriter.Extractor, mode string, srcDsts map[string]io.WriteSeeker) error {
	var result error
	for src, dst := range srcDsts {
		f, err := os.Open(src)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open file: %s, %v", src, err)
			result = errors.Join(result, err)
			continue
		}
		defer f.Close()

		var extractFn func(context.Context, io.WriteSeeker, io.ReaderAt) error
		if mode == "strip-debug" {
			extractFn = e.StripDebug
		} else {
			extractFn = e.OnlyKeepDebug
		}

		if err := extractFn(ctx, dst, f); err != nil {
			fmt.Fprintf(os.Stderr, "failed to extract debug information: %s, %v", src, err)
			result = errors.Join(result, err)
		}
	}
	return result
}

func grpcConn(reg prometheus.Registerer, flags flags) (*grpc.ClientConn, error) {
	met := grpc_prometheus.NewClientMetrics()
	met.EnableClientHandlingTimeHistogram()
	reg.MustRegister(met)

	opts := []grpc.DialOption{
		grpc.WithUnaryInterceptor(
			met.UnaryClientInterceptor(),
		),
	}
	if flags.Upload.Insecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		config := &tls.Config{
			//nolint:gosec
			InsecureSkipVerify: flags.Upload.InsecureSkipVerify,
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(config)))
	}

	if flags.Upload.BearerToken != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(&perRequestBearerToken{
			token:    flags.Upload.BearerToken,
			insecure: flags.Upload.Insecure,
		}))
	}

	if flags.Upload.BearerTokenFile != "" {
		b, err := os.ReadFile(flags.Upload.BearerTokenFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read bearer token from file: %w", err)
		}
		opts = append(opts, grpc.WithPerRPCCredentials(&perRequestBearerToken{
			token:    string(b),
			insecure: flags.Upload.Insecure,
		}))
	}

	return grpc.Dial(flags.Upload.StoreAddress, opts...)
}

type perRequestBearerToken struct {
	token    string
	insecure bool
}

func (t *perRequestBearerToken) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + t.token,
	}, nil
}

func (t *perRequestBearerToken) RequireTransportSecurity() bool {
	return !t.insecure
}

func uploadViaSignedURL(ctx context.Context, url string, r io.Reader) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, r)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("do upload request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return nil
}

func debuginfoTypeStringToPb(s string) debuginfopb.DebuginfoType {
	switch s {
	case "executable":
		return debuginfopb.DebuginfoType_DEBUGINFO_TYPE_EXECUTABLE
	case "sources":
		return debuginfopb.DebuginfoType_DEBUGINFO_TYPE_SOURCES
	default:
		return debuginfopb.DebuginfoType_DEBUGINFO_TYPE_DEBUGINFO_UNSPECIFIED
	}
}
