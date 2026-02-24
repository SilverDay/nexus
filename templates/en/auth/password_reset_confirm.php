<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Set New Password</title>
</head>
<body>
<main>
    <h1>Set New Password</h1>
    <?php if (!empty($message)): ?>
        <div role="alert" aria-live="polite"><?php echo $e($message); ?></div>
    <?php endif; ?>

    <form method="post" action="/ui/password-reset/confirm" novalidate>
        <input type="hidden" name="csrf_token" value="<?php echo $e($csrfToken); ?>">

        <label for="token">Reset token</label>
        <input id="token" name="token" type="text" required>

        <label for="new_password">New password</label>
        <input id="new_password" name="new_password" type="password" required minlength="12" autocomplete="new-password">

        <button type="submit">Update password</button>
    </form>
</main>
</body>
</html>
