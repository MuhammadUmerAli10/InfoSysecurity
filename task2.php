<?php

class AESCipher {
    private $cipher;
    private $key;
    private $iv;
    
    public function __construct($key, $mode = 'cbc') {
        $this->cipher = 'aes-256-' . strtolower($mode);
        $this->key = hash('sha256', $key, true);
        
        if ($mode !== 'ecb') {
            $this->iv = openssl_random_pseudo_bytes(openssl_cipher_iv_length($this->cipher));
        } else {
            $this->iv = ''; 
        }
    }
    
    public function encrypt($plaintext) {
        $ciphertext = openssl_encrypt($plaintext, $this->cipher, $this->key, OPENSSL_RAW_DATA, $this->iv);
        return base64_encode($this->iv . $ciphertext);
    }
    
    public function decrypt($encryptedText) {
        $data = base64_decode($encryptedText);
        $ivLength = openssl_cipher_iv_length($this->cipher);
        
        if ($this->cipher !== 'aes-256-ecb') {
            $this->iv = substr($data, 0, $ivLength);
            $ciphertext = substr($data, $ivLength);
        } else {
            $ciphertext = $data;
        }
        
        return openssl_decrypt($ciphertext, $this->cipher, $this->key, OPENSSL_RAW_DATA, $this->iv);
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'];
    $key = $_POST['key'];
    $mode = $_POST['mode'];
    $aes = new AESCipher($key, $mode);

    if ($action === 'encrypt') {
        $text = $_POST['text'];
        $encryptedText = $aes->encrypt($text);
        file_put_contents('encrypted.txt', $encryptedText);
        echo "<div class='alert alert-success text-center'>Encrypted text saved to file!</div>";
    } elseif ($action === 'decrypt' && isset($_FILES['encfile'])) {
        if ($_FILES['encfile']['error'] === UPLOAD_ERR_OK) {
            $fileData = file_get_contents($_FILES['encfile']['tmp_name']);
            $decryptedText = $aes->decrypt($fileData);
            echo "<div class='alert alert-info text-center'>Decrypted Text: " . htmlspecialchars($decryptedText) . "</div>";
        } else {
            echo "<div class='alert alert-danger text-center'>Error uploading file.</div>";
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>AES Encryption/Decryption</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {
            background-color: #fff;
        }
        .container {
            max-width: 600px;
            margin-top: 20px;
            text-align: center;
        }
        .card {
            border-radius: 15px;
            box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);
        }
        .btn {
            width: 100%;
        }
        .logo {
            max-width: 200px;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <img src="https://www.brandworks.lt/file_stor/u_images/VIKO/main_logo_VIKO_logo_maz_bw.png" alt="VIKO Logo" class="logo">
        <h2 class="text-center mb-4">AES Encryption/Decryption System</h2>
        <div class="card p-4">
            <form method="post" enctype="multipart/form-data">
                <div class="mb-3">
                    <label class="form-label">Secret Key:</label>
                    <input type="text" name="key" class="form-control" required>
                </div>
                <div class="mb-3">
                    <label class="form-label">Mode:</label>
                    <select name="mode" class="form-select">
                        <option value="ecb">ECB</option>
                        <option value="cbc">CBC</option>
                        <option value="cfb">CFB</option>
                    </select>
                </div>
                <div class="mb-3">
                    <label class="form-label">Enter Text (for encryption):</label>
                    <input type="text" name="text" class="form-control">
                </div>
                <div class="mb-3">
                    <label class="form-label">Or Upload Encrypted File (for decryption):</label>
                    <input type="file" name="encfile" class="form-control">
                </div>
                <button type="submit" name="action" value="encrypt" class="btn btn-primary mb-2">Encrypt & Save</button>
                <button type="submit" name="action" value="decrypt" class="btn btn-success">Decrypt Uploaded File</button>
            </form>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
