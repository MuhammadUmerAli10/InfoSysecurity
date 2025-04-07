<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
putenv("OPENSSL_CONF=C:\\xampp\\apache\\bin\\openssl.cnf");
// Generate RSA keys if not already generated
$keyDir = __DIR__;
$privateKeyFile = "$keyDir/private_key.pem";
$publicKeyFile = "$keyDir/public_key.pem";

if (!file_exists($privateKeyFile) || !file_exists($publicKeyFile)) {
    $keyPair = openssl_pkey_new([
        "private_key_bits" => 2048,
        "private_key_type" => OPENSSL_KEYTYPE_RSA
    ]);

    if (!$keyPair) {
        die("Failed to generate key pair: " . openssl_error_string());
    }

    if (!openssl_pkey_export($keyPair, $privateKey)) {
        die("Failed to export private key: " . openssl_error_string());
    }

    $publicKeyDetails = openssl_pkey_get_details($keyPair);
    $publicKey = $publicKeyDetails["key"] ?? null;

    if (!$publicKey) {
        die("Failed to extract public key: " . openssl_error_string());
    }

    file_put_contents($privateKeyFile, $privateKey);
    file_put_contents($publicKeyFile, $publicKey);
}

$decryptedText = "";
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $inputText = $_POST['plaintext'] ?? '';
    $action = $_POST['action'] ?? '';

    $publicKey = file_get_contents($publicKeyFile);
    $privateKey = file_get_contents($privateKeyFile);

    if ($action === 'encrypt' && $inputText) {
        if (!openssl_public_encrypt($inputText, $encrypted, $publicKey)) {
            die("Encryption failed: " . openssl_error_string());
        }
        $encoded = base64_encode($encrypted);
        file_put_contents('rsa_encrypted.txt', $encoded);
        echo "<div class='alert alert-success text-center'>Encrypted and saved to file!</div>";
    }

    if ($action === 'decrypt') {
        $encoded = file_get_contents('rsa_encrypted.txt');
        $encrypted = base64_decode($encoded);
        if (!openssl_private_decrypt($encrypted, $decryptedText, $privateKey)) {
            die("Decryption failed: " . openssl_error_string());
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>RSA Encryption/Decryption</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #f8f9fa; }
        .container { max-width: 600px; margin-top: 50px; }
        .card { border-radius: 15px; box-shadow: 0 0 10px rgba(0, 0, 0, 0.1); }
        .btn { width: 100%; }
    </style>
</head>
<body>
<div class="container">
    <h2 class="text-center mb-4">RSA Encryption/Decryption System</h2>
    <div class="card p-4">
        <form method="post">
            <div class="mb-3">
                <label class="form-label">Enter Plaintext:</label>
                <input type="text" name="plaintext" class="form-control">
            </div>
            <button type="submit" name="action" value="encrypt" class="btn btn-primary mb-2">Encrypt & Save</button>
            <button type="submit" name="action" value="decrypt" class="btn btn-success">Decrypt from File</button>
        </form>
    </div>
    <?php if ($decryptedText): ?>
        <div class="alert alert-info text-center mt-3">
            Decrypted Text: <strong><?= htmlspecialchars($decryptedText) ?></strong>
        </div>
    <?php endif; ?>
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>