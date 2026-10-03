fmt:
    taplo fmt
    cargo fmt
    rumdl fmt .
    rumdl check --fix .

check:
    cargo check