<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>TOTP Enrollment</title>
</head>
<body>
<main>
    <h1>TOTP Enrollment</h1>
    <?php if (!empty($message)): ?>
        <div role="alert" aria-live="polite"><?php echo $e($message); ?></div>
    <?php endif; ?>

    <section aria-labelledby="start-enrollment">
        <h2 id="start-enrollment">Start Enrollment</h2>
        <form method="post" action="/ui/totp/enroll/begin" novalidate>
            <input type="hidden" name="csrf_token" value="<?php echo $e($csrfToken); ?>">
            <button type="submit">Generate Provisioning URI</button>
        </form>
    </section>

    <?php if (!empty($provisioningUri)): ?>
        <section aria-labelledby="provisioning-uri">
            <h2 id="provisioning-uri">Provisioning URI</h2>
            <p>Copy this URI into your authenticator app:</p>
            <textarea rows="4" cols="80" readonly><?php echo $e($provisioningUri); ?></textarea>
        </section>
    <?php endif; ?>

    <section aria-labelledby="confirm-enrollment">
        <h2 id="confirm-enrollment">Confirm Enrollment</h2>
        <form method="post" action="/ui/totp/enroll/confirm" novalidate>
            <input type="hidden" name="csrf_token" value="<?php echo $e($csrfToken); ?>">

            <label for="otp">One-time code</label>
            <input id="otp" name="otp" type="text" inputmode="numeric" autocomplete="one-time-code" required>

            <button type="submit">Confirm TOTP</button>
        </form>
    </section>

    <section aria-labelledby="recovery-codes">
        <h2 id="recovery-codes">Recovery Codes</h2>
        <form method="post" action="/ui/recovery-codes/regenerate" novalidate>
            <input type="hidden" name="csrf_token" value="<?php echo $e($csrfToken); ?>">
            <button type="submit">Regenerate Recovery Codes</button>
        </form>

        <?php if (!empty($recoveryCodes) && is_array($recoveryCodes)): ?>
            <p>Save these one-time recovery codes securely. Each code can be used once.</p>
            <ul>
                <?php foreach ($recoveryCodes as $code): ?>
                    <li><code><?php echo $e((string) $code); ?></code></li>
                <?php endforeach; ?>
            </ul>
        <?php endif; ?>
    </section>
</main>
</body>
</html>
