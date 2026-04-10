# Contributing to mehfil-bridge

Thanks for your interest. Contributions are welcome — here's how things work.

## Bug reports

Open an issue on GitHub. Include:
- What you were doing
- What you expected
- What actually happened
- OS, Go version, and how you're running the bridge

## Pull requests

- Keep PRs focused — one thing per PR
- Run `go vet ./...` and `go build ./...` before opening the PR — both must pass clean
- Format with `gofmt` (or `goimports`)
- The bridge must remain a single-binary, zero-config drop-in — avoid adding required flags or persistent storage

## Security issues

Please **do not** open a public issue for security vulnerabilities. Reach out on Twitter at [@chirag](https://twitter.com/chirag).

## License

By submitting a PR you agree that your contribution will be licensed under the [MIT License](LICENSE).
