use messtar::{
    handshake::Handshake,
    identity::Identity,
    session::Session,
};

fn main() {
    println!("=== Messtar Secure Demo ===\n");

    // ── 1. Генерация Ed25519 identity ────────────────────────
    let alice_id = Identity::generate();
    let bob_id   = Identity::generate();
    println!("✅ Identity ключи сгенерированы");

    // ── 2. Handshake с подписями ─────────────────────────────
    let alice_hs = Handshake::new();
    let bob_hs   = Handshake::new();

    let alice_pub = alice_hs.public_key;
    let bob_pub   = bob_hs.public_key;

    // Каждая сторона подписывает свой X25519 публичный ключ
    let alice_sig = alice_id.sign_public_key(alice_pub.as_bytes());
    let bob_sig   = bob_id.sign_public_key(bob_pub.as_bytes());

    // Каждая сторона проверяет подпись другой стороны
    Identity::verify_public_key(
        &bob_id.verifying_key,
        bob_pub.as_bytes(),
        &bob_sig,
    ).expect("❌ Bob подпись невалидна!");

    Identity::verify_public_key(
        &alice_id.verifying_key,
        alice_pub.as_bytes(),
        &alice_sig,
    ).expect("❌ Alice подпись невалидна!");

    println!("✅ Ed25519 подписи проверены — MITM невозможен");

    // ── 3. Согласование ключей ───────────────────────────────
    let alice_key = alice_hs.derive_key(bob_pub);
    let bob_key   = bob_hs.derive_key(alice_pub);
    println!("✅ Общий ключ согласован\n");

    // ── 4. Сессия и обмен пакетами ───────────────────────────
    let alice_session = Session::new(alice_key);
    let bob_session   = Session::new(bob_key);

    for i in 1..=3u64 {
        let msg = format!("Сообщение #{i}");
        let packet = alice_session.send(msg.as_bytes()).unwrap();
        println!("📨 Alice → seq={} : {:?}", packet.seq_num, msg);

        let received = bob_session.receive(&packet).unwrap();
        println!("📩 Bob   ← seq={} : {:?}\n",
                 packet.seq_num,
                 std::str::from_utf8(&received).unwrap());
    }

    // ── 5. Replay Attack — проверка ──────────────────────────
    println!("⚔️  Попытка Replay Attack...");
    let old_packet = alice_session.send(b"replay me").unwrap();
    let _ = bob_session.receive(&old_packet).unwrap();

    // Повторяем тот же пакет
    match bob_session.receive(&old_packet) {
        Ok(_)  => println!("⚠️  Replay прошёл! (уязвимость)"),
        Err(e) => println!("✅ Replay отклонён: {e}"),
    }
}
