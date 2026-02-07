package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"

	"github.com/jingkaihe/matchlock/pkg/api"
	"github.com/jingkaihe/matchlock/pkg/image"
	"github.com/jingkaihe/matchlock/pkg/rpc"
	"github.com/jingkaihe/matchlock/pkg/sandbox"
	"github.com/jingkaihe/matchlock/pkg/state"
	"github.com/jingkaihe/matchlock/pkg/version"
	"github.com/jingkaihe/matchlock/pkg/vm"
)

var rootCmd = &cobra.Command{
	Use:     "matchlock",
	Short:   "A lightweight micro-VM sandbox for running llm agent securely",
	Long:    "Matchlock is a lightweight micro-VM sandbox for running llm agent\nsecurely with network interception and secret protection.",
	Version: version.Version,

	SilenceUsage:  true,
	SilenceErrors: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("matchlock %s (commit: %s, built: %s)\n", version.Version, version.GitCommit, version.BuildTime)
	},
}

var runCmd = &cobra.Command{
	Use:   "run [flags] -- <command>",
	Short: "Run a command in a new sandbox",
	Long: `Run a command in a new sandbox.

Secrets (--secret):
  Secrets are injected via MITM proxy - the real value never enters the VM.
  The VM sees a placeholder, which is replaced with the real value in HTTP headers.

  Formats:
    NAME=VALUE@host1,host2     Inline secret value for specified hosts
    NAME@host1,host2           Read secret from $NAME environment variable

  Note: When using sudo, env vars are not preserved. Use 'sudo -E' or pass inline.

Volume Mounts (-v):
  Guest paths are relative to workspace (or use full workspace paths):
  ./mycode:code                    Mounts to <workspace>/code
  ./data:/workspace/data           Same as above (explicit)
  /host/path:subdir:ro             Read-only mount to <workspace>/subdir

Wildcard Patterns for --allow-host:
  *                      Allow all hosts
  *.example.com          Allow all subdomains (api.example.com, a.b.example.com)
  api-*.example.com      Allow pattern match (api-v1.example.com, api-prod.example.com)`,
	Example: `  matchlock run --image alpine:latest -it sh
  matchlock run --image python:3.12-alpine python3 -c 'print(42)'
  matchlock run --image alpine:latest --rm=false   # keep VM alive after exit
  matchlock exec <vm-id> echo hello                # exec into running VM

  # With secrets (MITM replaces placeholder in HTTP requests)
  export ANTHROPIC_API_KEY=sk-xxx
  matchlock run --image python:3.12-alpine \
    --secret ANTHROPIC_API_KEY@api.anthropic.com \
    python call_api.py`,
	Args: cobra.ArbitraryArgs,
	RunE: runRun,
}

var buildCmd = &cobra.Command{
	Use:   "build [flags] <image-or-context>",
	Short: "Build rootfs from container image or Dockerfile",
	Long: `Build a rootfs from a container image, or build from a Dockerfile using BuildKit-in-VM.

When used with -f/--file, boots a privileged VM with BuildKit to build the Dockerfile.
The build context is the directory argument (defaults to current directory).`,
	Example: `  matchlock build alpine:latest
  matchlock build -t myapp:latest alpine:latest
  matchlock build -f Dockerfile -t myapp:latest .
  matchlock build -f Dockerfile -t myapp:latest ./myapp`,
	Args: cobra.ExactArgs(1),
	RunE: runBuild,
}

var listCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List all sandboxes",
	RunE:    runList,
}

var getCmd = &cobra.Command{
	Use:   "get <id>",
	Short: "Get details of a sandbox",
	Args:  cobra.ExactArgs(1),
	RunE:  runGet,
}

var killCmd = &cobra.Command{
	Use:   "kill <id>",
	Short: "Kill a running sandbox",
	RunE:  runKill,
}

var execCmd = &cobra.Command{
	Use:   "exec [flags] <id> -- <command>",
	Short: "Execute a command in a running sandbox",
	Long: `Execute a command in a running sandbox.

The sandbox must have been started with --rm=false to remain running.`,
	Example: `  matchlock exec vm-abc123 echo hello
  matchlock exec vm-abc123 -it sh`,
	Args: cobra.MinimumNArgs(1),
	RunE: runExec,
}

var rmCmd = &cobra.Command{
	Use:     "rm <id>",
	Aliases: []string{"remove"},
	Short:   "Remove a stopped sandbox",
	RunE:    runRemove,
}

var pruneCmd = &cobra.Command{
	Use:   "prune",
	Short: "Remove all stopped sandboxes",
	RunE:  runPrune,
}

var rpcCmd = &cobra.Command{
	Use:   "rpc",
	Short: "Run in RPC mode (for programmatic access)",
	RunE:  runRPC,
}

func init() {
	runCmd.Flags().String("image", "", "Container image (required)")
	runCmd.Flags().String("workspace", api.DefaultWorkspace, "Guest mount point for VFS")
	runCmd.Flags().StringSlice("allow-host", nil, "Allowed hosts (can be repeated)")
	runCmd.Flags().StringSliceP("volume", "v", nil, "Volume mount (host:guest or host:guest:ro)")
	runCmd.Flags().StringSlice("secret", nil, "Secret (NAME=VALUE@host1,host2 or NAME@host1,host2)")
	runCmd.Flags().Int("cpus", api.DefaultCPUs, "Number of CPUs")
	runCmd.Flags().Int("memory", api.DefaultMemoryMB, "Memory in MB")
	runCmd.Flags().Int("timeout", api.DefaultTimeoutSeconds, "Timeout in seconds")
	runCmd.Flags().Int("disk-size", api.DefaultDiskSizeMB, "Disk size in MB")
	runCmd.Flags().BoolP("tty", "t", false, "Allocate a pseudo-TTY")
	runCmd.Flags().BoolP("interactive", "i", false, "Keep STDIN open")
	runCmd.Flags().Bool("pull", false, "Always pull image from registry (ignore cache)")
	runCmd.Flags().Bool("rm", true, "Remove sandbox after command exits (set --rm=false to keep running)")
	runCmd.Flags().Bool("privileged", false, "Skip in-guest security restrictions (seccomp, cap drop, no_new_privs)")
	runCmd.Flags().StringP("workdir", "w", "", "Working directory inside the sandbox (default: workspace path)")
	runCmd.MarkFlagRequired("image")

	viper.BindPFlag("run.image", runCmd.Flags().Lookup("image"))
	viper.BindPFlag("run.workspace", runCmd.Flags().Lookup("workspace"))
	viper.BindPFlag("run.allow-host", runCmd.Flags().Lookup("allow-host"))
	viper.BindPFlag("run.volume", runCmd.Flags().Lookup("volume"))
	viper.BindPFlag("run.secret", runCmd.Flags().Lookup("secret"))
	viper.BindPFlag("run.cpus", runCmd.Flags().Lookup("cpus"))
	viper.BindPFlag("run.memory", runCmd.Flags().Lookup("memory"))
	viper.BindPFlag("run.timeout", runCmd.Flags().Lookup("timeout"))
	viper.BindPFlag("run.disk-size", runCmd.Flags().Lookup("disk-size"))
	viper.BindPFlag("run.tty", runCmd.Flags().Lookup("tty"))
	viper.BindPFlag("run.interactive", runCmd.Flags().Lookup("interactive"))
	viper.BindPFlag("run.pull", runCmd.Flags().Lookup("pull"))

	viper.BindPFlag("run.rm", runCmd.Flags().Lookup("rm"))

	execCmd.Flags().BoolP("tty", "t", false, "Allocate a pseudo-TTY")
	execCmd.Flags().BoolP("interactive", "i", false, "Keep STDIN open")
	execCmd.Flags().StringP("workdir", "w", "", "Working directory inside the sandbox (default: workspace path)")

	buildCmd.Flags().Bool("pull", false, "Always pull image from registry (ignore cache)")
	buildCmd.Flags().StringP("tag", "t", "", "Tag the image locally")
	buildCmd.Flags().StringP("file", "f", "", "Path to Dockerfile (enables BuildKit-in-VM build)")
	buildCmd.Flags().Int("build-cpus", 2, "Number of CPUs for BuildKit VM")
	buildCmd.Flags().Int("build-memory", 2048, "Memory in MB for BuildKit VM")

	listCmd.Flags().Bool("running", false, "Show only running VMs")
	viper.BindPFlag("list.running", listCmd.Flags().Lookup("running"))

	killCmd.Flags().Bool("all", false, "Kill all running VMs")
	viper.BindPFlag("kill.all", killCmd.Flags().Lookup("all"))

	rmCmd.Flags().Bool("stopped", false, "Remove all stopped VMs")
	viper.BindPFlag("rm.stopped", rmCmd.Flags().Lookup("stopped"))

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(execCmd)
	rootCmd.AddCommand(buildCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(getCmd)
	rootCmd.AddCommand(killCmd)
	rootCmd.AddCommand(rmCmd)
	rootCmd.AddCommand(pruneCmd)
	rootCmd.AddCommand(rpcCmd)
	rootCmd.AddCommand(versionCmd)

	viper.SetEnvPrefix("MATCHLOCK")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runRun(cmd *cobra.Command, args []string) error {
	imageName, _ := cmd.Flags().GetString("image")
	cpus, _ := cmd.Flags().GetInt("cpus")
	memory, _ := cmd.Flags().GetInt("memory")
	timeout, _ := cmd.Flags().GetInt("timeout")
	tty, _ := cmd.Flags().GetBool("tty")
	interactive, _ := cmd.Flags().GetBool("interactive")
	workspace, _ := cmd.Flags().GetString("workspace")
	allowHosts, _ := cmd.Flags().GetStringSlice("allow-host")
	volumes, _ := cmd.Flags().GetStringSlice("volume")
	secrets, _ := cmd.Flags().GetStringSlice("secret")
	rm, _ := cmd.Flags().GetBool("rm")

	workdir, _ := cmd.Flags().GetString("workdir")
	privileged, _ := cmd.Flags().GetBool("privileged")
	interactiveMode := tty && interactive
	pull, _ := cmd.Flags().GetBool("pull")
	diskSize, _ := cmd.Flags().GetInt("disk-size")

	command := api.ShellQuoteArgs(args)

	if rm && len(args) == 0 && !interactiveMode {
		return fmt.Errorf("command required (or use --rm=false to start without a command)")
	}

	var ctx context.Context
	var cancel context.CancelFunc

	if cmd.Flags().Changed("timeout") {
		ctx, cancel = context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	} else {
		ctx, cancel = context.WithCancel(context.Background())
	}
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	builder := image.NewBuilder(&image.BuildOptions{
		ForcePull: pull,
	})

	buildResult, err := builder.Build(ctx, imageName)
	if err != nil {
		return fmt.Errorf("building rootfs: %w", err)
	}
	if buildResult.Cached {
		fmt.Printf("Using cached image %s\n", imageName)
	} else {
		fmt.Printf("Built rootfs from %s (%.1f MB)\n", imageName, float64(buildResult.Size)/(1024*1024))
	}
	sandboxOpts := &sandbox.Options{RootfsPath: buildResult.RootfsPath}

	vfsConfig := &api.VFSConfig{Workspace: workspace}
	if len(volumes) > 0 {
		mounts := make(map[string]api.MountConfig)
		for _, vol := range volumes {
			hostPath, guestPath, readonly, err := api.ParseVolumeMount(vol, workspace)
			if err != nil {
				return fmt.Errorf("invalid volume mount %q: %w", vol, err)
			}
			mounts[guestPath] = api.MountConfig{
				Type:     "real_fs",
				HostPath: hostPath,
				Readonly: readonly,
			}
		}
		vfsConfig.Mounts = mounts
	}

	var parsedSecrets map[string]api.Secret
	if len(secrets) > 0 {
		parsedSecrets = make(map[string]api.Secret)
		for _, s := range secrets {
			name, secret, err := api.ParseSecret(s)
			if err != nil {
				return fmt.Errorf("invalid secret %q: %w", s, err)
			}
			parsedSecrets[name] = secret
		}
	}

	config := &api.Config{
		Image:      imageName,
		Privileged: privileged,
		Resources: &api.Resources{
			CPUs:           cpus,
			MemoryMB:       memory,
			DiskSizeMB:     diskSize,
			TimeoutSeconds: timeout,
		},
		Network: &api.NetworkConfig{
			AllowedHosts:    allowHosts,
			BlockPrivateIPs: true,
			Secrets:         parsedSecrets,
		},
		VFS: vfsConfig,
	}

	sb, err := sandbox.New(ctx, config, sandboxOpts)
	if err != nil {
		return fmt.Errorf("creating sandbox: %w", err)
	}

	if err := sb.Start(ctx); err != nil {
		sb.Close()
		return fmt.Errorf("starting sandbox: %w", err)
	}

	// Start exec relay server so `matchlock exec` can connect from another process
	execRelay := sandbox.NewExecRelay(sb)
	stateMgr := state.NewManager()
	execSocketPath := stateMgr.ExecSocketPath(sb.ID())
	if err := execRelay.Start(execSocketPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to start exec relay: %v\n", err)
	}
	defer execRelay.Stop()

	if !rm {
		fmt.Fprintf(os.Stderr, "Sandbox %s is running\n", sb.ID())
		fmt.Fprintf(os.Stderr, "  Connect: matchlock exec %s -it bash\n", sb.ID())
		fmt.Fprintf(os.Stderr, "  Stop:    matchlock kill %s\n", sb.ID())
	}

	if interactiveMode {
		exitCode := runInteractive(ctx, sb, command, workdir)
		if rm {
			sb.Close()
		}
		os.Exit(exitCode)
	}

	if len(args) > 0 {
		var opts *api.ExecOptions
		if workdir != "" {
			opts = &api.ExecOptions{WorkingDir: workdir}
		}
		result, err := sb.Exec(ctx, command, opts)
		if err != nil {
			if rm {
				sb.Close()
			}
			return fmt.Errorf("executing command: %w", err)
		}

		os.Stdout.Write(result.Stdout)
		os.Stderr.Write(result.Stderr)

		if rm {
			sb.Close()
			os.Exit(result.ExitCode)
		}
	}

	if !rm {
		// Block until signal — keeps the sandbox alive for `matchlock exec`
		<-ctx.Done()
		sb.Close()
	}

	return nil
}

func runExec(cmd *cobra.Command, args []string) error {
	vmID := args[0]
	cmdArgs := args[1:]

	tty, _ := cmd.Flags().GetBool("tty")
	interactive, _ := cmd.Flags().GetBool("interactive")
	workdir, _ := cmd.Flags().GetString("workdir")
	interactiveMode := tty && interactive

	if len(cmdArgs) == 0 && !interactiveMode {
		return fmt.Errorf("command required (or use -it for interactive mode)")
	}

	mgr := state.NewManager()
	vmState, err := mgr.Get(vmID)
	if err != nil {
		return fmt.Errorf("VM %s not found: %w", vmID, err)
	}
	if vmState.Status != "running" {
		return fmt.Errorf("VM %s is not running (status: %s)", vmID, vmState.Status)
	}

	execSocketPath := mgr.ExecSocketPath(vmID)
	if _, err := os.Stat(execSocketPath); err != nil {
		return fmt.Errorf("exec socket not found for %s (was it started with --rm=false?)", vmID)
	}

	command := api.ShellQuoteArgs(cmdArgs)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	if interactiveMode {
		return runExecInteractive(ctx, execSocketPath, command, workdir)
	}

	result, err := sandbox.ExecViaRelay(ctx, execSocketPath, command, workdir)
	if err != nil {
		return fmt.Errorf("exec failed: %w", err)
	}

	os.Stdout.Write(result.Stdout)
	os.Stderr.Write(result.Stderr)
	os.Exit(result.ExitCode)
	return nil
}

func runExecInteractive(ctx context.Context, execSocketPath, command, workdir string) error {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("-it requires a TTY")
	}

	cols, rows, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		rows, cols = 24, 80
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("setting raw mode: %w", err)
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	exitCode, err := sandbox.ExecInteractiveViaRelay(ctx, execSocketPath, command, workdir, uint16(rows), uint16(cols), os.Stdin, os.Stdout)
	if err != nil {
		term.Restore(int(os.Stdin.Fd()), oldState)
		return fmt.Errorf("interactive exec failed: %w", err)
	}

	term.Restore(int(os.Stdin.Fd()), oldState)
	os.Exit(exitCode)
	return nil
}

func runBuild(cmd *cobra.Command, args []string) error {
	dockerfile, _ := cmd.Flags().GetString("file")
	tag, _ := cmd.Flags().GetString("tag")
	pull, _ := cmd.Flags().GetBool("pull")

	if dockerfile != "" {
		return runDockerfileBuild(cmd, args[0], dockerfile, tag)
	}

	imageRef := args[0]
	builder := image.NewBuilder(&image.BuildOptions{
		ForcePull: pull,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	fmt.Printf("Building rootfs from %s...\n", imageRef)
	result, err := builder.Build(ctx, imageRef)
	if err != nil {
		return err
	}

	if tag != "" {
		if err := builder.SaveTag(tag, result); err != nil {
			return fmt.Errorf("saving tag: %w", err)
		}
		fmt.Printf("Tagged: %s\n", tag)
	}

	fmt.Printf("Built: %s\n", result.RootfsPath)
	fmt.Printf("Digest: %s\n", result.Digest)
	fmt.Printf("Size: %.1f MB\n", float64(result.Size)/(1024*1024))
	return nil
}

func runDockerfileBuild(cmd *cobra.Command, contextDir, dockerfile, tag string) error {
	if tag == "" {
		return fmt.Errorf("-t/--tag is required when building from a Dockerfile")
	}

	cpus, _ := cmd.Flags().GetInt("build-cpus")
	memory, _ := cmd.Flags().GetInt("build-memory")

	// Resolve paths
	absContext, err := filepath.Abs(contextDir)
	if err != nil {
		return fmt.Errorf("resolve context dir: %w", err)
	}
	if info, err := os.Stat(absContext); err != nil || !info.IsDir() {
		return fmt.Errorf("build context %q is not a directory", contextDir)
	}

	absDockerfile, err := filepath.Abs(dockerfile)
	if err != nil {
		return fmt.Errorf("resolve Dockerfile: %w", err)
	}
	if _, err := os.Stat(absDockerfile); err != nil {
		return fmt.Errorf("Dockerfile not found: %s", dockerfile)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	// Step 1: Build the BuildKit rootless image
	buildkitImage := "moby/buildkit:rootless"
	fmt.Fprintf(os.Stderr, "Preparing BuildKit image (%s)...\n", buildkitImage)
	builder := image.NewBuilder(&image.BuildOptions{})
	buildResult, err := builder.Build(ctx, buildkitImage)
	if err != nil {
		return fmt.Errorf("building BuildKit rootfs: %w", err)
	}

	// Step 2: Create a privileged sandbox with the build context mounted
	// All VFS mounts must be under /workspace since guest-fused mounts FUSE there.
	// Layout: /workspace/context (build context), /workspace/output (build output)
	// The Dockerfile dir is either under context or written to /workspace/dockerfile/
	dockerfileName := filepath.Base(absDockerfile)
	dockerfileInContext := filepath.Join(absContext, dockerfileName)
	dockerfileDir := filepath.Dir(absDockerfile)

	mounts := map[string]api.MountConfig{
		"/workspace":         {Type: "memory"},
		"/workspace/context": {Type: "real_fs", HostPath: absContext, Readonly: true},
		"/workspace/output":  {Type: "memory"},
	}

	guestDockerfileDir := "/workspace/context"
	if _, err := os.Stat(dockerfileInContext); os.IsNotExist(err) {
		// Dockerfile is outside the build context — mount its directory separately
		mounts["/workspace/dockerfile"] = api.MountConfig{Type: "real_fs", HostPath: dockerfileDir, Readonly: true}
		guestDockerfileDir = "/workspace/dockerfile"
	}

	config := &api.Config{
		Image:      buildkitImage,
		Privileged: true,
		Resources: &api.Resources{
			CPUs:           cpus,
			MemoryMB:       memory,
			DiskSizeMB:     api.DefaultDiskSizeMB,
			TimeoutSeconds: 1800,
		},
		Network: &api.NetworkConfig{},
		VFS: &api.VFSConfig{
			Workspace: "/workspace",
			Mounts:    mounts,
		},
	}

	sandboxOpts := &sandbox.Options{RootfsPath: buildResult.RootfsPath}
	sb, err := sandbox.New(ctx, config, sandboxOpts)
	if err != nil {
		return fmt.Errorf("creating BuildKit sandbox: %w", err)
	}
	defer sb.Close()

	if err := sb.Start(ctx); err != nil {
		return fmt.Errorf("starting BuildKit sandbox: %w", err)
	}

	// Step 3: Start BuildKit daemon and run the build in a single exec
	// We must combine daemon start + build into one exec call because each sb.Exec()
	// spawns a separate process — a backgrounded daemon from one exec would be killed
	// when that shell exits, before the next exec can use it.
	fmt.Fprintf(os.Stderr, "Starting BuildKit daemon and building image from %s...\n", dockerfile)

	execOpts := &api.ExecOptions{WorkingDir: "/"}

	// Run BuildKit as root directly (no rootlesskit). The VM is already an isolated
	// environment, so running buildkitd as root is safe. We use a helper script
	// to avoid complex shell quoting.
	//
	// Key settings:
	// - native snapshotter: avoids overlayfs xattr complexity
	// - TMPDIR on ext4: ensures containerd-mount temp dirs support xattr
	// - type=docker output: compatible with go-containerregistry tarball.ImageFromPath
	buildScript := fmt.Sprintf(
		`cat > /tmp/buildkit-run.sh << 'SCRIPT'
export HOME=/root
export TMPDIR=/var/lib/buildkit/tmp
mkdir -p $TMPDIR
SOCK=/tmp/buildkit.sock
buildkitd --root /var/lib/buildkit \
  --addr unix://$SOCK \
  --oci-worker-snapshotter native \
  >/tmp/buildkitd.log 2>&1 &
BKPID=$!
for i in $(seq 1 30); do [ -S $SOCK ] && break; sleep 1; done
if [ ! -S $SOCK ]; then
  echo "BuildKit daemon failed to start" >&2
  cat /tmp/buildkitd.log >&2
  exit 1
fi
echo "BuildKit daemon ready" >&2
buildctl --addr unix://$SOCK build \
  --frontend dockerfile.v0 \
  --local context=/workspace/context \
  --local dockerfile=%s \
  --output type=docker,dest=/workspace/output/image.tar
RC=$?
[ $RC -ne 0 ] && { echo "=== buildkitd log ===" >&2; cat /tmp/buildkitd.log >&2; }
kill $BKPID 2>/dev/null
exit $RC
SCRIPT
`+`chmod +x /tmp/buildkit-run.sh && /tmp/buildkit-run.sh`,
		guestDockerfileDir,
	)
	result, execErr := sb.Exec(ctx, buildScript, execOpts)
	if execErr != nil {
		return fmt.Errorf("BuildKit build: %w", execErr)
	}
	os.Stderr.Write(result.Stdout)
	os.Stderr.Write(result.Stderr)
	if result.ExitCode != 0 {
		return fmt.Errorf("BuildKit build failed (exit %d)", result.ExitCode)
	}

	// Step 4: Read the OCI tarball from VFS and import into local store
	fmt.Fprintf(os.Stderr, "Importing built image as %s...\n", tag)

	tarballData, err := sb.ReadFile(ctx, "/workspace/output/image.tar")
	if err != nil {
		return fmt.Errorf("read built image: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "matchlock-build-*.tar")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.Write(tarballData); err != nil {
		tmpFile.Close()
		return fmt.Errorf("write temp tarball: %w", err)
	}
	tmpFile.Close()

	importFile, err := os.Open(tmpFile.Name())
	if err != nil {
		return fmt.Errorf("open temp tarball: %w", err)
	}
	defer importFile.Close()

	importResult, err := builder.Import(ctx, importFile, tag)
	if err != nil {
		return fmt.Errorf("import built image: %w", err)
	}

	fmt.Printf("Successfully built and tagged %s\n", tag)
	fmt.Printf("Rootfs: %s\n", importResult.RootfsPath)
	fmt.Printf("Size: %.1f MB\n", float64(importResult.Size)/(1024*1024))
	return nil
}

func runInteractive(ctx context.Context, sb *sandbox.Sandbox, command, workdir string) int {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintln(os.Stderr, "Error: -it requires a TTY")
		return 1
	}

	cols, rows, err := term.GetSize(int(os.Stdin.Fd()))
	if err != nil {
		rows, cols = 24, 80
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error setting raw mode: %v\n", err)
		return 1
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	resizeCh := make(chan [2]uint16, 1)
	winchCh := make(chan os.Signal, 1)
	signal.Notify(winchCh, syscall.SIGWINCH)
	go func() {
		for range winchCh {
			if c, r, err := term.GetSize(int(os.Stdin.Fd())); err == nil {
				select {
				case resizeCh <- [2]uint16{uint16(r), uint16(c)}:
				default:
				}
			}
		}
	}()
	defer signal.Stop(winchCh)
	defer close(resizeCh)

	interactiveMachine, ok := sb.Machine().(vm.InteractiveMachine)
	if !ok {
		fmt.Fprintln(os.Stderr, "Error: interactive mode not supported on this backend")
		return 1
	}

	opts := sb.PrepareExecEnv()
	if workdir != "" {
		opts.WorkingDir = workdir
	}

	exitCode, err := interactiveMachine.ExecInteractive(ctx, command, opts, uint16(rows), uint16(cols), os.Stdin, os.Stdout, resizeCh)
	if err != nil {
		term.Restore(int(os.Stdin.Fd()), oldState)
		fmt.Fprintf(os.Stderr, "\nError: %v\n", err)
		return 1
	}

	return exitCode
}

func runList(cmd *cobra.Command, args []string) error {
	running, _ := cmd.Flags().GetBool("running")

	mgr := state.NewManager()
	states, err := mgr.List()
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSTATUS\tIMAGE\tCREATED\tPID")

	for _, s := range states {
		if running && s.Status != "running" {
			continue
		}
		created := s.CreatedAt.Format("2006-01-02 15:04")
		pid := "-"
		if s.PID > 0 {
			pid = fmt.Sprintf("%d", s.PID)
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.ID, s.Status, s.Image, created, pid)
	}
	w.Flush()
	return nil
}

func runGet(cmd *cobra.Command, args []string) error {
	mgr := state.NewManager()
	s, err := mgr.Get(args[0])
	if err != nil {
		return err
	}

	output, _ := json.MarshalIndent(s, "", "  ")
	fmt.Println(string(output))
	return nil
}

func runKill(cmd *cobra.Command, args []string) error {
	all, _ := cmd.Flags().GetBool("all")
	mgr := state.NewManager()

	if all {
		states, _ := mgr.List()
		for _, s := range states {
			if s.Status == "running" {
				if err := mgr.Kill(s.ID); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to kill %s: %v\n", s.ID, err)
				} else {
					fmt.Printf("Killed %s\n", s.ID)
				}
			}
		}
		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("VM ID required (or use --all)")
	}

	if err := mgr.Kill(args[0]); err != nil {
		return err
	}
	fmt.Printf("Killed %s\n", args[0])
	return nil
}

func runRemove(cmd *cobra.Command, args []string) error {
	stopped, _ := cmd.Flags().GetBool("stopped")
	mgr := state.NewManager()

	if stopped {
		states, _ := mgr.List()
		for _, s := range states {
			if s.Status != "running" {
				if err := mgr.Remove(s.ID); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to remove %s: %v\n", s.ID, err)
				} else {
					fmt.Printf("Removed %s\n", s.ID)
				}
			}
		}
		return nil
	}

	if len(args) == 0 {
		return fmt.Errorf("VM ID required (or use --stopped)")
	}

	if err := mgr.Remove(args[0]); err != nil {
		return err
	}
	fmt.Printf("Removed %s\n", args[0])
	return nil
}

func runPrune(cmd *cobra.Command, args []string) error {
	mgr := state.NewManager()
	pruned, err := mgr.Prune()
	if err != nil {
		return err
	}

	for _, id := range pruned {
		fmt.Printf("Pruned %s\n", id)
	}
	fmt.Printf("Pruned %d VMs\n", len(pruned))
	return nil
}

func runRPC(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	factory := func(ctx context.Context, config *api.Config) (rpc.VM, error) {
		if config.Image == "" {
			return nil, fmt.Errorf("image is required")
		}

		builder := image.NewBuilder(&image.BuildOptions{})

		result, err := builder.Build(ctx, config.Image)
		if err != nil {
			return nil, fmt.Errorf("failed to build rootfs: %w", err)
		}

		return sandbox.New(ctx, config, &sandbox.Options{RootfsPath: result.RootfsPath})
	}

	return rpc.RunRPC(ctx, factory)
}
