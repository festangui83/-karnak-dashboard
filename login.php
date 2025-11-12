<?php 
    declare(strict_types=1); 
    require 'config.php'; 
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') 
    { 
        http_response_code(405); 
        echo json_encode(['errors' => ['Método no permitido']]); 
        exit; 
    } 
    $username = isset($_POST['username']) ? trim((string)$_POST['username']) : ''; 
    $password = isset($_POST['password']) ? $_POST['password'] : ''; 
    $remember = isset($_POST['remember']) ? (bool)$_POST['remember'] : false; 
    $errors = []; 
    if ($username === '') $errors[] = 'Usuario es requerido'; 
    if ($password === '' || mb_strlen((string)$password) < 8) $errors[] = 'La contraseña debe tener al menos 8 caracteres'; 
    if (!empty($errors)) 
    { 
        http_response_code(400); 
        echo json_encode(['errors' => $errors]); 
        exit; 
    } 
    try 
    { 
        $pdo = dbConnect(); 
        $stmt = $pdo->prepare('SELECT id, username, password_hash FROM users WHERE username = :u OR email = :e LIMIT 1'); 
        $stmt->execute(['u' => $username, 'e' => $username]); 
        $user = $stmt->fetch(); 
        if ($user && password_verify($password, (string)$user['password_hash'])) 
        { 
            session_regenerate_id(true); 
            $_SESSION['user_id'] = (int)$user['id']; 
            $_SESSION['username'] = $user['username']; 
            if ($remember) 
            { 
                $token = bin2hex(random_bytes(32)); 
                $pdo->prepare('UPDATE users SET remember_token = :t WHERE id = :id')->execute(['t'=>$token, 'id'=>$user['id']]); 
                setcookie('remember_me_token', $token, time() + (60*60*24*30), '/', '', true, true); 
                setcookie('remember_me_user', $user['id'], time() + (60*60*24*30), '/', '', true, true); 
            } 
            echo json_encode(['success' => true]); 
            exit;
            } 
            else 
            { 
                http_response_code(400); 
                echo json_encode(['errors' => ['Credenciales incorrectas']]); 
                exit; 
            } 
        } 
        catch (PDOException $e) 
        { 
            http_response_code(500); 
            echo json_encode(['errors' => ['Error del servidor']]); 
            exit; 
        } 
?>