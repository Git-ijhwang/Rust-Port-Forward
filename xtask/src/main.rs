use std::process::Command;
use clap::Parser;

#[derive(Parser)]
struct Options {
    #[clap(subcommand)]
    command: Subcommand,
}

#[derive(Parser)]
enum Subcommand {
    BuildEbpf {
        #[clap(long)]
        release: bool,
    },
}

fn main() -> anyhow::Result<()> {
    let opts = Options::parse();

    match opts.command {
        Subcommand::BuildEbpf { release } => {
            build_ebpf(release)?;
        }
    }

    Ok(())
}

fn build_ebpf(release: bool) -> anyhow::Result<()> {
    // 🎯 이게 진짜 핵심입니다: 실제로 cargo build 명령을 날리는 부분!
    let mut cmd = Command::new("cargo");
    cmd.args([
        "+nightly",
        "build",
        "-p", "port_forwarding-ebpf", // 커널 패키지 이름 프로젝트에 맞게 고치기!!
        "-Z", "build-std=core",
        "--target", "bpfel-unknown-none",
    ]);

    if release {
        cmd.arg("--release");
    }

    // 빌드 실행
    let status = cmd.status()?;
    if !status.success() {
        anyhow::bail!("eBPF 빌드 실패!");
    }

    println!("✅ eBPF 바이너리가 성공적으로 구워졌습니다!");
    Ok(())
}
