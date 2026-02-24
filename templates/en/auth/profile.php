<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Profile</title>
</head>
<body>
<main>
    <h1>Profile</h1>

    <?php if (!empty($message)): ?>
        <div role="alert" aria-live="polite"><?php echo $e($message); ?></div>
    <?php endif; ?>

    <form method="post" action="/ui/profile" novalidate>
        <input type="hidden" name="csrf_token" value="<?php echo $e($csrfToken); ?>">

        <label for="realname">Real name</label>
        <input
            id="realname"
            name="realname"
            type="text"
            value="<?php echo $e(isset($user['real_name']) ? (string) $user['real_name'] : ''); ?>"
            required
            minlength="2"
            maxlength="120"
        >

        <?php if (!empty($profileFieldDefinitions)): ?>
            <fieldset>
                <legend>Custom profile fields</legend>

                <?php foreach ($profileFieldDefinitions as $fieldKey => $definition): ?>
                    <label for="profile_<?php echo $e($fieldKey); ?>"><?php echo $e((string) ($definition['label'] ?? $fieldKey)); ?></label>
                    <input
                        id="profile_<?php echo $e($fieldKey); ?>"
                        <?php if (($definition['editable'] ?? false) === true): ?>
                            name="profile[<?php echo $e($fieldKey); ?>]"
                        <?php endif; ?>
                        type="text"
                        value="<?php echo $e($profileFields[$fieldKey] ?? ''); ?>"
                        <?php if (($definition['editable'] ?? false) !== true): ?>readonly aria-readonly="true"<?php endif; ?>
                        <?php if (($definition['required'] ?? false) === true && ($definition['editable'] ?? false) === true): ?>required<?php endif; ?>
                    >
                <?php endforeach; ?>
            </fieldset>
        <?php endif; ?>

        <button type="submit">Save profile</button>
    </form>
</main>
</body>
</html>
