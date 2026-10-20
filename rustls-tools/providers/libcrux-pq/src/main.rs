mod provider;

fn main() -> std::process::ExitCode {
    pqc_rustls::cli::main(provider::provider())
}
