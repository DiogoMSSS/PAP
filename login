<?php
session_start();
include __DIR__ . '/../connection/db.php';

$erro_nome = $erro_apelido = $erro_email = $erro_password = $erro_confirmar_password = "";
$nome = $apelido = $email = $password = $confirmar_password = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  $nome = $_POST['nome'] ?? '';
  $apelido = $_POST['apelido'] ?? '';
  $email = trim($_POST['email'] ?? '');
  $password = $_POST['password'] ?? '';
  $confirmar_password = $_POST['confirm_password'] ?? '';
  $erros = false;

  if (empty($nome) || !preg_match('/^[A-Za-zÀ-ÖØ-öø-ÿ\s]+$/', $nome)) {
    $erro_nome = "O nome deve conter apenas letras e não pode estar vazio.";
    $erros = true;
  }

  if (empty($apelido) || !preg_match('/^[A-Za-zÀ-ÖØ-öø-ÿ\s]+$/', $apelido)) {
    $erro_apelido = "O apelido deve conter apenas letras e não pode estar vazio.";
    $erros = true;
  }

  if (empty($email)) {
    $erro_email = "Por favor, insira seu email.";
    $erros = true;
  } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $erro_email = "Formato de email inválido.";
    $erros = true;
  } else {
    $stmt = $pdo->prepare("SELECT COUNT(*) FROM utilizador WHERE email = :email");
    $stmt->bindParam(':email', $email);
    $stmt->execute();
    if ($stmt->fetchColumn() > 0) {
      $erro_email = "Este email já está registrado.";
      $erros = true;
    }
  }

  if (empty($password)) {
    $erro_password = "Por favor, insira uma senha.";
    $erros = true;
  } elseif (
    strlen($password) < 8 ||
    !preg_match('/[A-Z]/', $password) ||
    !preg_match('/[a-z]/', $password) ||
    !preg_match('/[0-9]/', $password) ||
    !preg_match('/[\W]/', $password)
  ) {
    $erro_password = "A senha deve conter pelo menos 8 caracteres, incluindo letra maiúscula, minúscula, número e símbolo.";
    $erros = true;
  }

  if ($password !== $confirmar_password) {
    $erro_confirmar_password = "As senhas não coincidem.";
    $erros = true;
  }

  if (!$erros) {
    $hashed_password = password_hash($password, PASSWORD_BCRYPT);
    $stmt = $pdo->prepare("INSERT INTO utilizador (nome, apelido, email, password, admin) VALUES (:nome, :apelido, :email, :password, FALSE)");
    $stmt->bindParam(':nome', $nome);
    $stmt->bindParam(':apelido', $apelido);
    $stmt->bindParam(':email', $email);
    $stmt->bindParam(':password', $hashed_password);
    if ($stmt->execute()) {
      $_SESSION['nome'] = $nome;
      $_SESSION['email'] = $email;
      header("Location: ../geral/pap.php");
      exit;
    } else {
      echo "Erro ao criar conta. Tente novamente.";
    }
  }
}
?>

<!DOCTYPE html>
<html lang="pt-pt">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Registo</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background-color: #34495e;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      margin: 0;
      color: #ecf0f1;
    }

    .login-container {
      background: #2c3e50;
      padding: 40px;
      border-radius: 12px;
      box-shadow: 0 8px 20px rgba(0, 0, 0, 0.3);
      width: 340px;
    }

    h1 {
      text-align: center;
      color: #f39c12;
    }

    input[type="text"],
    input[type="email"],
    input[type="password"] {
      width: 100%;
      padding: 10px;
      margin: 8px 0;
      border: 1px solid #7f8c8d;
      border-radius: 6px;
      background-color: #2c3e50;
      color: #ecf0f1;
      box-sizing: border-box;
      font-size: 1rem;
      outline: none;
    }

    input:focus {
      border-color: #f39c12;
    }

    .erro {
      font-size: 0.85rem;
      color: #e74c3c;
      margin: 0 0 5px 0;
    }

    input[type="submit"] {
      background-color: #f39c12;
      color: #2c3e50;
      border: none;
      padding: 12px;
      border-radius: 8px;
      cursor: pointer;
      width: 100%;
      font-weight: bold;
      font-size: 1.1rem;
      transition: background-color 0.3s ease;
      margin-top: 10px;
    }

    input[type="submit"]:hover {
      background-color: #e67e22;
    }

    input[type="submit"]:active {
      background-color: #d35400;
    }

    .password-wrapper {
      position: relative;
    }

    .password-wrapper input {
      padding-right: 40px;
    }

    .toggle-password {
      position: absolute;
      top: 50%;
      right: 10px;
      transform: translateY(-50%);
      cursor: pointer;
      width: 20px;
      height: 20px;
    }

    .toggle-password svg {
      width: 20px;
      height: 20px;
      fill: #bdc3c7;
    }

    #eyeOpen2 {
      display: none;
    }

    .forgot-password-link {
          display: block;
          text-align: center;
          margin-top: 10px;
          color: #f39c12;
          text-decoration: none;
          font-weight: 500;
    }

    .forgot-password-link:hover {
          text-decoration: underline;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <h1>Registro</h1>
    <form action="" method="post" autocomplete="off">
      <input type="text" name="nome" placeholder="Nome" value="<?= htmlspecialchars($nome) ?>" required>
      <div class="erro"><?= $erro_nome ?></div>

      <input type="text" name="apelido" placeholder="Apelido" value="<?= htmlspecialchars($apelido) ?>" required>
      <div class="erro"><?= $erro_apelido ?? '' ?></div>

      <input type="email" name="email" placeholder="Email" value="<?= htmlspecialchars($email) ?>" required>
      <div class="erro"><?= $erro_email ?></div>

      <div class="password-wrapper">
        <input type="password" name="password" id="password" placeholder="Palavra-passe" required>
        <span class="toggle-password" onclick="togglePassword('password', 'eyeOpen2', 'eyeClosed2')">
          <svg id="eyeClosed2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 26 26">
            <path d="M12 4.5C7 4.5 2.7 7.6 1 12c1.7 4.4 6 7.5 11 7.5s9.3-3.1 11-7.5c-1.7-4.4-6-7.5-11-7.5zm0 13c-3.2 0-6-2.5-6-5.5S8.8 6.5 12 6.5s6 2.5 6 5.5-2.8 5.5-6 5.5zM3 3l18 18-1.5 1.5L1.5 4.5 3 3z"/>
          </svg>
          <svg id="eyeOpen2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20">
            <path d="M12 6c-3.3 0-6.3 1.8-8 4.5 1.7 2.7 4.7 4.5 8 4.5s6.3-1.8 8-4.5C18.3 7.8 15.3 6 12 6zm0 7.5c-1.7 0-3-1.3-3-3s1.3-3 3-3 3 1.3 3 3-1.3 3-3 3z"/>
          </svg>
        </span>
      </div>
      <div class="erro"><?= $erro_password ?></div>

      <div class="password-wrapper">
        <input type="password" name="confirm_password" id="confirm_password" placeholder="Confirmar palavra-passe" required>
        <span class="toggle-password" onclick="togglePassword('confirm_password', 'eyeOpenConfirm', 'eyeClosedConfirm')">
          <svg id="eyeClosedConfirm" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 26 26">
           <path d="M12 4.5C7 4.5 2.7 7.6 1 12c1.7 4.4 6 7.5 11 7.5s9.3-3.1 11-7.5c-1.7-4.4-6-7.5-11-7.5zm0 13c-3.2 0-6-2.5-6-5.5S8.8 6.5 12 6.5s6 2.5 6 5.5-2.8 5.5-6 5.5zM3 3l18 18-1.5 1.5L1.5 4.5 3 3z"/>
          </svg>
          <svg id="eyeOpenConfirm" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" style="display:none;">
            <path d="M12 6c-3.3 0-6.3 1.8-8 4.5 1.7 2.7 4.7 4.5 8 4.5s6.3-1.8 8-4.5C18.3 7.8 15.3 6 12 6zm0 7.5c-1.7 0-3-1.3-3-3s1.3-3 3-3 3 1.3 3 3-1.3 3-3 3z"/>
          </svg>
        </span>
      </div>
      <div class="erro"><?= $erro_confirmar_password ?></div>
      <input type="submit" value="Criar Conta">
    </form>
    <a href="/pap/login/login.php" class="forgot-password-link">Já têm conta? <span></a>
  </div>

  <script>
    function togglePassword(inputId, eyeOpenId, eyeClosedId) {
      const input = document.getElementById(inputId);
      const eyeOpen = document.getElementById(eyeOpenId);
      const eyeClosed = document.getElementById(eyeClosedId);

      if (input.type === 'password') {
        input.type = 'text';
        eyeOpen.style.display = 'inline';
        eyeClosed.style.display = 'none';
      } else {
        input.type = 'password';
        eyeOpen.style.display = 'none';
        eyeClosed.style.display = 'inline';
      }
    }
    document.addEventListener("DOMContentLoaded", () => {
      const passwordInput = document.querySelector('input[name="password"]');
      const strengthText = document.createElement("div");
      strengthText.style.fontSize = "12px";
      strengthText.style.textAlign = "center";
      strengthText.style.marginTop = "-1px";
      strengthText.style.marginBottom = "1px";
      passwordInput.insertAdjacentElement("afterend", strengthText);

      passwordInput.addEventListener("input", () => {
        const value = passwordInput.value;
        let strength = 0;

        if (value.length >= 8) strength++;
        if (/[A-Z]/.test(value)) strength++;
        if (/[a-z]/.test(value)) strength++;
        if (/[0-9]/.test(value)) strength++;
        if (/[\W]/.test(value)) strength++;

        let msg = "";
        let color = "";

        if (strength <= 2) {
          msg = "Senha fraca";
          color = "red";
        } else if (strength === 3 || strength === 4) {
          msg = "Senha média";
          color = "orange";
        } else if (strength === 5) {
          msg = "Senha forte";
          color = "green";
        }

        strengthText.textContent = msg;
        strengthText.style.color = color;
      });
    });
  </script>
</body>
</html>
