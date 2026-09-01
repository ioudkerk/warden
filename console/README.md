# Admin console

A React SPA served by the `mgmt` role and protected by Warden itself (SPEC §14).
Delivered in **M6**; the simulator (§14.2) and the UI-element bindings editor (§11.3)
are its two load-bearing screens.

The directory is a declared npm workspace from M0 so that the console's toolchain,
lint rules and CI job exist before the first component is written.
