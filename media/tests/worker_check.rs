#[tokio::test(flavor = "multi_thread")]
async fn worker_count() {
    eprintln!("WORKERS: {}", tokio::runtime::Handle::current().metrics().num_workers());
}
