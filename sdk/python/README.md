# warden-sdk

The Python backend SDK. Delivered in **M3**; design in
[`../../docs/sdk-backend-python.md`](../../docs/sdk-backend-python.md).

The package skeleton exists from M0 so the Python toolchain is wired into CI before
there is anything to break. Its most important deliverable is not the client but
**M3-4**: a runner for the language-neutral conformance corpus in
[`../../conformance`](../../conformance), which is what makes "the SDK and the server
agree" a tested claim rather than an assumption.
