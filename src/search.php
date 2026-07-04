<?php
declare(strict_types=1);

require_once __DIR__ . '/db_config.php';   // provides $pdo (PDO instance)

/** Small helper: encode for the HTML body/text context. */
function h(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

$keyword = (string)($_GET['keyword'] ?? '');

// Escape LIKE metacharacters so they are treated as literal text, then wrap
// the value (not the SQL) with wildcards.
$escaped = str_replace(['\\', '%', '_'], ['\\\\', '\\%', '\\_'], $keyword);
$likeValue = '%' . $escaped . '%';

// Command plane is fixed here; :kw is a bound placeholder, never concatenated.
$stmt = $pdo->prepare(
    "SELECT id, name, illness_history
       FROM patient_records
      WHERE name LIKE :kw ESCAPE '\\'"
);
$stmt->execute([':kw' => $likeValue]);
$rows = $stmt->fetchAll();

header('Content-Type: text/html; charset=UTF-8');

if ($rows) {
    foreach ($rows as $row) {
        // Context-aware output encoding on EVERY interpolated value.
        echo '<div>Result found for keyword: ' . h($keyword) . '<br>';
        echo 'Patient: ' . h($row['name'])
           . ' | History: ' . h($row['illness_history'])
           . '</div><hr>';
    }
} else {
    echo 'No records found for: ' . h($keyword);
}
