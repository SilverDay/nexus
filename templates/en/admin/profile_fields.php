<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Admin: Profile Fields</title>
</head>
<body>
<main>
    <h1>Admin: Profile Field Definitions</h1>

    <?php if (!empty($message)): ?>
        <div role="alert" aria-live="polite"><?php echo $e($message); ?></div>
    <?php endif; ?>

    <h2>Existing Definitions</h2>
    <ul>
        <?php foreach (($definitions ?? []) as $fieldKey => $definition): ?>
            <li>
                <strong><?php echo $e($fieldKey); ?></strong>
                (label: <?php echo $e((string) ($definition['label'] ?? $fieldKey)); ?>,
                visible: <?php echo (($definition['user_visible'] ?? true) ? 'yes' : 'no'); ?>,
                editable: <?php echo (($definition['user_editable'] ?? true) ? 'yes' : 'no'); ?>,
                admin-visible: <?php echo (($definition['admin_visible'] ?? true) ? 'yes' : 'no'); ?>)
                <form method="post" action="/ui/admin/profile-fields/delete" style="display:inline">
                    <input type="hidden" name="csrf_token" value="<?php echo $e($csrfToken); ?>">
                    <input type="hidden" name="field_key" value="<?php echo $e($fieldKey); ?>">
                    <button type="submit">Delete</button>
                </form>
            </li>
        <?php endforeach; ?>
    </ul>

    <h2>Upsert Definition</h2>
    <form method="post" action="/ui/admin/profile-fields/upsert" novalidate>
        <input type="hidden" name="csrf_token" value="<?php echo $e($csrfToken); ?>">

        <label for="field_key">Field key</label>
        <input id="field_key" name="field_key" type="text" required>

        <label for="label">Label</label>
        <input id="label" name="label" type="text" required>

        <label for="max_length">Max length</label>
        <input id="max_length" name="max_length" type="number" min="1" max="4000">

        <label for="pattern">Pattern (regex)</label>
        <input id="pattern" name="pattern" type="text">

        <label>
            <input name="required" type="checkbox" value="1">
            Required
        </label>

        <label>
            <input name="user_visible" type="checkbox" value="1" checked>
            User visible
        </label>

        <label>
            <input name="user_editable" type="checkbox" value="1" checked>
            User editable
        </label>

        <label>
            <input name="admin_visible" type="checkbox" value="1" checked>
            Admin visible
        </label>

        <button type="submit">Save definition</button>
    </form>
</main>
</body>
</html>
