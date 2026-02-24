<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Verify Email</title>
</head>
<body>
<main>
    <h1>Verify Email</h1>
    <?php if (!empty($message)): ?>
        <div role="alert" aria-live="polite"><?php echo $e($message); ?></div>
    <?php endif; ?>

    <form method="post" action="/ui/verify-email" novalidate>
        <input type="hidden" name="csrf_token" value="<?php echo $e($csrfToken); ?>">

        <label for="token">Verification token</label>
        <input id="token" name="token" type="text" required>

        <button type="submit">Verify</button>
    </form>
</main>
</body>
</html>
