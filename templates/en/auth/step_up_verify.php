<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Step-up Verification</title>
</head>
<body>
<main>
    <h1>Step-up Verification</h1>
    <?php if (!empty($message)): ?>
        <div role="alert" aria-live="polite"><?php echo $e($message); ?></div>
    <?php endif; ?>

    <form method="post" action="/ui/step-up/verify" novalidate>
        <input type="hidden" name="csrf_token" value="<?php echo $e($csrfToken); ?>">

        <label for="otp">One-time code</label>
        <input id="otp" name="otp" type="text" inputmode="numeric" autocomplete="one-time-code" required>

        <p>Or use a recovery code:</p>
        <label for="recovery_code">Recovery code</label>
        <input id="recovery_code" name="recovery_code" type="text" autocomplete="one-time-code">

        <button type="submit">Verify</button>
    </form>
</main>
</body>
</html>
