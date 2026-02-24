<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Login</title>
</head>
<body>
<main>
    <h1>Login</h1>
    <?php if (!empty($message)): ?>
        <div role="alert" aria-live="polite"><?php echo $e($message); ?></div>
    <?php endif; ?>

    <form method="post" action="/ui/login" novalidate>
        <input type="hidden" name="csrf_token" value="<?php echo $e($csrfToken); ?>">

        <label for="identifier">Username or Email</label>
        <input id="identifier" name="identifier" type="text" required autocomplete="username">

        <label for="password">Password</label>
        <input id="password" name="password" type="password" required autocomplete="current-password">

        <label>
            <input name="remember_me" type="checkbox" value="1">
            Remember me
        </label>

        <button type="submit">Login</button>
    </form>

    <p>
        <a href="/oidc/google/start">Continue with Google</a>
    </p>
</main>
</body>
</html>
