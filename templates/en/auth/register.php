<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Register</title>
</head>
<body>
<main>
    <h1>Register</h1>
    <?php if (!empty($message)): ?>
        <div role="alert" aria-live="polite"><?php echo $e($message); ?></div>
    <?php endif; ?>

    <form method="post" action="/ui/register" novalidate>
        <input type="hidden" name="csrf_token" value="<?php echo $e($csrfToken); ?>">

        <label for="username">Username</label>
        <input id="username" name="username" type="text" required minlength="3" maxlength="50" autocomplete="username">

        <label for="email">Email</label>
        <input id="email" name="email" type="email" required autocomplete="email">

        <label for="realname">Real name</label>
        <input id="realname" name="realname" type="text" required minlength="2" maxlength="120" autocomplete="name">

        <label for="password">Password</label>
        <input id="password" name="password" type="password" required minlength="12" autocomplete="new-password">

        <?php if (!empty($profileFieldDefinitions)): ?>
            <fieldset>
                <legend>Custom profile fields</legend>

                <?php foreach ($profileFieldDefinitions as $fieldKey => $definition): ?>
                    <label for="profile_<?php echo $e($fieldKey); ?>"><?php echo $e((string) ($definition['label'] ?? $fieldKey)); ?></label>
                    <input
                        id="profile_<?php echo $e($fieldKey); ?>"
                        name="profile[<?php echo $e($fieldKey); ?>]"
                        type="text"
                        <?php if (($definition['required'] ?? false) === true): ?>required<?php endif; ?>
                    >
                <?php endforeach; ?>
            </fieldset>
        <?php endif; ?>

        <button type="submit">Create account</button>
    </form>

    <p>
        <a href="/oidc/google/start">Continue with Google</a>
    </p>
</main>
</body>
</html>
