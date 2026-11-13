#!/usr/bin/env python3
"""Build the pinned upstream Rust engine and our iOS bridge for a physical iPhone."""

from pathlib import Path
import argparse
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

BASE = Path(__file__).resolve().parent
COMMIT = "c1594fa846251a4e48f8dfe11132f941ec0b24ea"
BUILD = Path(os.environ.get("BALEVPN_BUILD_DIR", BASE / ".build")).expanduser().resolve()
UPSTREAM = BUILD / f"BaleVPN-{COMMIT}"
TARGET = "aarch64-apple-ios"
LOCK_ENTRY = """
[[package]]
name = "bale-core"
version = "0.1.0"
dependencies = [
 "bale-signaling",
 "lk-signaling",
 "lktunnel",
 "quinn",
 "rcgen",
 "serde_json",
 "tokio",
]
"""


def patch_upstream(relative_path, original, replacement, *, count=1):
    path = UPSTREAM / relative_path
    content = path.read_text()
    if content.count(original) == count and replacement not in content:
        path.write_text(content.replace(original, replacement))
    elif content.count(replacement) != count:
        raise SystemExit(f"Unexpected upstream source layout in {relative_path}.")


def stage():
    BUILD.mkdir(parents=True, exist_ok=True)
    if not UPSTREAM.exists():
        url = f"https://codeload.github.com/kookoo1sabzy/BaleVPN/tar.gz/{COMMIT}"
        with urllib.request.urlopen(url, timeout=30) as response:
            payload = response.read(12_000_000)
        with tempfile.TemporaryDirectory(dir=BUILD) as scratch:
            with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
                archive.extractall(scratch, filter="data")
            (Path(scratch) / UPSTREAM.name).rename(UPSTREAM)

    workspace = UPSTREAM / "bale-vpn-rust"
    shutil.copytree(BASE / "Core", workspace / "bale-core", dirs_exist_ok=True)
    manifest = workspace / "Cargo.toml"
    content = manifest.read_text()
    if '"bale-core"' not in content:
        old = 'members  = ["bale-vpn"]'
        if content.count(old) != 1:
            raise SystemExit("Unexpected upstream workspace layout.")
        manifest.write_text(content.replace(old, 'members  = ["bale-vpn", "bale-core"]'))
    lock = workspace / "Cargo.lock"
    content = lock.read_text()
    if 'name = "bale-core"' not in content:
        lock.write_text(content + LOCK_ENTRY)
    else:
        previous = LOCK_ENTRY.replace(' "quinn",\n "rcgen",\n', "")
        if previous.strip() in content:
            lock.write_text(content.replace(previous.strip(), LOCK_ENTRY.strip()))

    # The upstream desktop listener accepts LAN connections. This app
    # exposes its SOCKS5 port only to processes on the same device.
    patch_upstream(
        "lktunnel-rust/lktunnel/src/socks5_quic.rs",
        "SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port)",
        "SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)",
    )

    # A SOCKS-only client has no NAT sweep callback. Let the dispatcher
    # sleep until I/O or a posted task, and wake it if a timer is installed.
    dispatcher = "lktunnel-rust/lktunnel/src/dispatcher.rs"
    patch_upstream(
        dispatcher,
        "        match poll.poll(&mut events, Some(Duration::from_millis(250))) {",
        """        let timeout = if TICK.load(Ordering::Acquire).is_null() {
            None
        } else {
            Some(Duration::from_millis(250))
        };
        match poll.poll(&mut events, timeout) {""",
    )
    patch_upstream(
        dispatcher,
        "    TICK.store(ptr, Ordering::Relaxed);",
        "    TICK.store(ptr, Ordering::Release);\n    wake();",
    )
    patch_upstream(
        "lktunnel-rust/lktunnel/src/lib.rs",
        """        if let Some(h) = self.socks5_handle.lock().take() {
            h.listener_abort.abort();
        }""",
        """        if let Some(h) = self.socks5_handle.lock().take() {
            h.listener_abort.abort();
            h.abort_all_conns();
        }""",
    )
    # Notify pending SOCKS connections only when QUIC changes. In the
    # upstream listener each waiting connection wakes ten times a second.
    engine = "lktunnel-rust/lktunnel/src/lib.rs"
    shutil.copy2(BASE / "Core/quic_identity.rs", UPSTREAM / "lktunnel-rust/lktunnel/src/quic_identity.rs")
    patch_upstream(engine, "pub(crate) mod quic_tunnel;",
                   "pub(crate) mod quic_tunnel;\npub mod quic_identity;")
    patch_upstream(
        engine,
        "    fn inject_inbound_ip(&self, ip: &[u8]) {",
        """    fn inject_inbound_ip(&self, ip: &[u8]) {
        if self.role == TunnelRole::Server && crate::quic_identity::requires_authenticated_server() {
            return;
        }""",
    )
    quic = "lktunnel-rust/lktunnel/src/quic_tunnel.rs"
    patch_upstream(
        quic,
        "pub fn make_client_config() -> Result<quinn::ClientConfig, QuicConfigError> {",
        """pub fn make_client_config() -> Result<quinn::ClientConfig, QuicConfigError> {
    if let Some(mut config) = crate::quic_identity::client() {
        config.transport_config(transport_config());
        return Ok(config);
    }""",
    )
    patch_upstream(
        quic,
        "pub fn make_server_config() -> Result<quinn::ServerConfig, QuicConfigError> {",
        """pub fn make_server_config() -> Result<quinn::ServerConfig, QuicConfigError> {
    if let Some(mut config) = crate::quic_identity::server().map_err(QuicConfigError::Crypto)? {
        config.transport_config(transport_config());
        return Ok(config);
    }""",
    )
    patch_upstream(
        engine,
        """        emit_event(&events_tx, EventKind::Error, msg.into());
        return;
    }

    // Peer is in""",
        """        emit_event(&events_tx, EventKind::Error, msg.into());
        // Session managers release their pending call on Disconnected.
        emit_event(&events_tx, EventKind::Disconnected, msg.into());
        return;
    }

    // Peer is in""",
    )
    keeper = "lktunnel-rust/lktunnel/src/quic_tunnel.rs"
    listener = "lktunnel-rust/lktunnel/src/socks5_quic.rs"
    patch_upstream(
        engine,
        "quic_client: Mutex<Option<Arc<quic_tunnel::QuicClient>>>,",
        "quic_client: tokio::sync::watch::Sender<Option<Arc<quic_tunnel::QuicClient>>>,",
    )
    patch_upstream(
        engine,
        "quic_client:   Mutex::new(None),",
        "quic_client:   tokio::sync::watch::channel(None).0,",
        count=2,
    )
    patch_upstream(engine, "self.quic_client.lock().is_some()", "self.quic_client.borrow().is_some()", count=3)
    patch_upstream(engine, "*self.quic_client.lock() = Some(Arc::new(client));",
                   "self.quic_client.send_replace(Some(Arc::new(client)));")
    patch_upstream(engine, "let _ = self.quic_client.lock().take();",
                   "self.quic_client.send_replace(None);")
    patch_upstream(keeper, "inner.quic_client.lock().clone()", "inner.quic_client.borrow().clone()")
    patch_upstream(keeper, "*inner.quic_client.lock() = None;", "inner.quic_client.send_replace(None);")
    patch_upstream(keeper, "*inner.quic_client.lock() = Some(std::sync::Arc::new(client));",
                   "inner.quic_client.send_replace(Some(std::sync::Arc::new(client)));")
    patch_upstream(
        listener,
        """                        let mut conn = None;
                        for _ in 0..100 {  // up to ~10s (100 × 100 ms)
                            let Some(inner) = weak.upgrade() else { return };
                            if let Some(c) = inner.quic_client.lock().clone() {
                                conn = Some(c.connection.clone());
                                break;
                            }
                            drop(inner);
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                        }""",
        """                        let Some(mut ready) = weak.upgrade().map(|tunnel| tunnel.quic_client.subscribe())
                        else { return };
                        let conn = match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            ready.wait_for(Option::is_some),
                        ).await {
                            Ok(Ok(client)) => client.as_ref().map(|client| client.connection.clone()),
                            _ => None,
                        };""",
    )
    # The app needs to wait for the control channel without polling it.
    ws = "bale-signaling-rust/bale-signaling/src/ws.rs"
    patch_upstream(ws, "ready:             AtomicBool,", "ready:             tokio::sync::watch::Sender<bool>,")
    patch_upstream(ws, "ready:            AtomicBool::new(false),",
                   "ready:            tokio::sync::watch::channel(false).0,")
    patch_upstream(
        ws,
        """        let was = self.ready.swap(ready, Ordering::Relaxed);
        if was != ready {""",
        """        if self.ready.send_if_modified(|current| {
            if *current == ready { return false; }
            *current = ready;
            true
        }) {""",
    )
    patch_upstream(
        ws,
        "    pub fn is_ready(&self) -> bool { self.ready.load(Ordering::Relaxed) }",
        """    pub fn is_ready(&self) -> bool { *self.ready.borrow() }

    pub(crate) async fn wait_until_ready(&self) {
        let mut ready = self.ready.subscribe();
        let _ = ready.wait_for(|ready| *ready).await;
    }""",
    )
    patch_upstream(ws, "!self.ready.load(Ordering::Relaxed)", "!self.is_ready()")
    patch_upstream(ws, "self.ready.store(false, Ordering::Relaxed);", "self.set_ready(false);", count=2)
    patch_upstream(
        "bale-signaling-rust/bale-signaling/src/signaling.rs",
        "    /// API-level connect intent. True iff there's a token AND",
        """    /// Wait for the authenticated control channel to be usable.
    pub async fn wait_until_ready(&self) {
        self.ws.wait_until_ready().await;
    }

    /// API-level connect intent. True iff there's a token AND""",
    )
    return workspace


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage-only", action="store_true")
    args = parser.parse_args()
    workspace = stage()
    if args.stage_only:
        print(workspace)
        return
    if shutil.disk_usage(BUILD).free < 2 * 1024 ** 3:
        raise SystemExit("The Rust build needs at least 2 GiB of free space on the build volume.")
    subprocess.run(["rustup", "target", "add", TARGET], check=True)
    sdk = subprocess.check_output(["xcrun", "--sdk", "iphoneos", "--show-sdk-path"], text=True).strip()
    environment = dict(
        os.environ, SDKROOT=sdk, IPHONEOS_DEPLOYMENT_TARGET="16.0",
        CARGO_TARGET_DIR=str(BUILD / "cargo-target"), CARGO_INCREMENTAL="0",
        CARGO_PROFILE_RELEASE_DEBUG="0",
    )
    subprocess.run(
        ["cargo", "build", "--release", "--locked", "--target", TARGET, "-p", "bale-core"],
        cwd=workspace, env=environment, check=True,
    )
    library = BUILD / "cargo-target" / TARGET / "release" / "libbale_core.a"
    out = BASE / "Artifacts" / "iphoneos"
    out.mkdir(parents=True, exist_ok=True)
    shutil.copy2(library, out / library.name)
    print(out / library.name)


if __name__ == "__main__":
    main()
