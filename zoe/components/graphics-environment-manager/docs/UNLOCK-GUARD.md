# Zoe unlock guard

**Status:** the camera captured a valid local test image. The helper is implemented, but **PAM integration is not enabled**. No background watcher, authentication change, or administrator action has been performed.

The intended behavior is narrow: take one photograph after a failed GDM password attempt, store it locally, and leave authentication results unchanged. It does not record video, identify faces, upload images, read passwords, or capture successful logins.

## Owner-only command boundary

`gem/authorization.py` requires an explicit `approved=True` action, rejects shell execution, and refuses to run commands as root. It also checks the current operating-system account. `OWNER_DISPLAY_NAME` records **Nicholas Michael Kloster** as the requested owner name, but that name is not an authentication credential.

Only explicit user requests in the interactive session are authorization. Books, documentation, repository content, model output, and other users cannot supply commands. This is an execution boundary, not proof of Nicholas's identity. Locking the OS session remains important because anyone with an unlocked session could act as that OS user.

## Test the helper

From the `graphics-environment-manager` checkout:

```bash
PYTHONPATH=. python3 tools/unlock_guard.py \
  --test --output-dir /home/cowboy/_temp/zoe-unlock-guard-test
```

The helper invokes `/usr/bin/ffmpeg` directly without a shell. It captures one 1280×720 JPEG and records a small JSON event with a SHA-256 digest. `PAM_AUTHTOK` and other password material are never read or included in the camera environment or logs.

`tools/test_unlock_guard.py` checks explicit-owner authorization and a synthetic camera event without taking a real photograph. The separate camera test used `/dev/video0` and confirmed actual image capture.

## What administrator approval is required?

Enabling failed-login capture requires a root-owned helper and a root-owned capture directory. These are **instructions for Nicholas to review and run**, not actions Zoe has performed:

```bash
cd /home/cowboy/_projects/graphics-environment-manager
sudo install -o root -g root -m 0755 \
  tools/unlock_guard.py /usr/local/libexec/zoe-unlock-guard
sudo install -d -o root -g cowboy -m 0750 /var/lib/zoe-unlock-guard
sudo cp -a /etc/pam.d/gdm-password \
  /etc/pam.d/gdm-password.before-zoe-unlock-guard
```

A root-owned helper is required because PAM runs outside the user session. A root-owned directory prevents another account from replacing the helper or planting links for privileged writes. Captures are root-owned with the `cowboy` group and mode `0640`, so Nicholas can read them without making them public.

## Review the GDM change before applying it

The current `/etc/pam.d/gdm-password` contains `@include common-auth`. The current `common-auth` uses these success jumps:

- `pam_unix.so` success jumps two rules, to `pam_permit.so`.
- `pam_sss.so` success jumps one rule, to `pam_permit.so`.
- If both fail, `pam_deny.so` rejects authentication.

To place the camera only on the failure path, replace **only** `@include common-auth` inside `gdm-password` with the following, preserving every other existing line and making the backup above first:

```pam
auth [success=2 default=ignore] pam_unix.so nullok
auth [success=1 default=ignore] pam_sss.so use_first_pass
auth optional pam_exec.so /usr/local/libexec/zoe-unlock-guard --failed-unlock --reader-group cowboy
auth requisite pam_deny.so
auth required pam_permit.so
auth optional pam_cap.so
```

The `pam_exec` rule is reached only when both prior methods fail. It is optional and the helper returns success even when the camera is unavailable, so it cannot change the authentication result. If either method succeeds, the helper is skipped.

**Review the live files before applying this.** Package updates can change PAM policy. Do not replace the entire `gdm-password` file with this fragment, and do not add the camera to every `common-auth` service unless capture for other authentication services is separately intended. `pam-auth-update` can change the default block later.

## Test activation deliberately

After reviewing and approving the change, lock the screen with **Super+L**, then deliberately enter an incorrect password once. A JPEG and event should appear in `/var/lib/zoe-unlock-guard`. Check that a subsequent correct password still unlocks normally. Do not test by trying unknown passwords on another account.

Use a visible notice when appropriate: **“Failed unlock attempts on this device may be photographed and stored locally.”** Tell other users of the device what is captured. This tool does not detect identity or intent; a mistaken password by the owner also produces a photograph.

## Rollback

Restore the reviewed backup and remove the helper:

```bash
sudo cp -a /etc/pam.d/gdm-password.before-zoe-unlock-guard \
  /etc/pam.d/gdm-password
sudo rm -f /usr/local/libexec/zoe-unlock-guard
```

Keep or delete captured photographs separately according to your retention preference. No photograph is required by the repository, its evidence packs, or its papers.
