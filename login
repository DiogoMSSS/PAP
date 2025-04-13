<?php
session_start();
include __DIR__ . '/../connection/db.php'; // Conexão com o banco de dados

// Ativar exibição de erros para depuração (remover em produção)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Função para limitar tentativas de login (Proteção contra Brute Force)
function is_brute_force($conn, $email) {
    $stmt = $conn->prepare("SELECT failed_attempts, last_attempt FROM utilizador WHERE email = :email");
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && $user['failed_attempts'] >= 5 && strtotime($user['last_attempt']) > time() - 300) {
        return true; // Bloqueia o login por 5 minutos após 5 tentativas falhas
    }
    return false;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = trim($_POST['password'] ?? '');
    $token = $_POST['g-recaptcha-response'] ?? ''; // Captcha
    

    // Verificação do Google reCAPTCHA
    $secretKey = 'SUA_CHAVE_SECRETA_DO_RECAPTCHA';
    $response = file_get_contents("https://www.google.com/recaptcha/api/siteverify?secret=$secretKey&response=$token");
    $responseKeys = json_decode($response, true);

    if (!$responseKeys["success"]) {
        die("Falha na verificação do CAPTCHA.");
    }

    if (is_brute_force($conn, $email)) {
        die("Muitas tentativas falhas. Tente novamente mais tarde.");
    }

    // Buscar usuário no banco de dados
    $sql = "SELECT id, nome, apelido, password, failed_attempts FROM utilizador WHERE email = :email";
    $stmt = $conn->prepare($sql);
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password'])) {
        // Resetar tentativas falhas
        $stmt = $conn->prepare("UPDATE utilizador SET failed_attempts = 0 WHERE email = :email");
        $stmt->bindParam(':email', $email);
        $stmt->execute();

        // Implementação de autenticação de dois fatores (2FA) com código temporário
        $codigo_2fa = rand(100000, 999999);
        $_SESSION['codigo_2fa'] = $codigo_2fa;
        $_SESSION['temp_user_id'] = $user['id'];
        $_SESSION['temp_user_nome'] = trim($user['nome'] . ' ' . $user['apelido']);

        // Enviar código por e-mail (Substituir pelo serviço de envio real)
        mail($email, "Seu código de autenticação", "Seu código de autenticação é: $codigo_2fa");

        header("Location: verificar_2fa.php"); // Redireciona para a página de verificação do 2FA
        exit;
    } else {
        // Atualizar tentativas falhas
        $stmt = $conn->prepare("UPDATE utilizador SET failed_attempts = failed_attempts + 1, last_attempt = NOW() WHERE email = :email");
        $stmt->bindParam(':email', $email);
        $stmt->execute();

        echo "Email ou senha incorretos.";
    }
}
?>

<!DOCTYPE html>
<html lang="pt-pt">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <script src="https://www.google.com/recaptcha/api.js" async defer></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            width: 320px;
        }
        h1 {
            text-align: center;
            color: #333;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 10px;
            margin: 10px 0;
            border: 1px solid #ccc;
            border-radius: 4px;
            box-sizing: border-box;
        }
        input[type="submit"] {
            background-color: #000;
            color: white;
            border: none;
            padding: 12px;
            border-radius: 4px;
            cursor: pointer;
            width: 100%;
        }
        input[type="submit"]:hover {
            background-color: #333;
        }
        .error {
            color: red;
            text-align: center;
        }
    </style>
</head>

<body>
    <div class="login-container">
        <h1>Login</h1>
        <form action="login.php" method="post">
            <input type="text" name="email" placeholder="Email" required autocomplete="off">
            <input type="password" name="password" placeholder="Password" required autocomplete="off">
            <div class="g-recaptcha" data-sitekey="SUA_CHAVE_PUBLICA_DO_RECAPTCHA"></div>
            <input type="submit" value="Entrar">
        </form>
    </div>
</body>
</html>
