<?php 
    declare(strict_types=1); 
    require 'config.php'; 
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') 
    { 
        http_response_code(405); 
        echo json_encode(['errors' => ['Método no permitido']]); 
        exit; 
    } 
    $token = isset($_POST['token']) ? $_POST['token'] : ''; 
    $new_password = isset($_POST['new_password']) ? $_POST['new_password'] : ''; 
    $confirm_password = isset($_POST['confirm_password']) ? $_POST['confirm_password'] : ''; 
    $errors = []; 
    if (empty($token)) $errors[] = 'Token es requerido'; 
    if (empty($new_password) || mb_strlen((string)$new_password) < 8) $errors[] = 'La contraseña debe tener al menos 8 caracteres'; 
    if ($new_password !== $confirm_password) $errors[] = 'Las contraseñas no coinciden'; 
    if (!empty($errors)) { http_response_code(400); 
    echo json_encode(['errors' => $errors]); 
    exit; 
    } 
    try 
    { 
        $pdo = dbConnect(); 
        $stmt = $pdo->prepare('SELECT id FROM users WHERE reset_token = :t AND reset_token_expires > NOW()'); 
        $stmt->execute(['t'=>$token]); 
        $user = $stmt->fetch(); 
        if (!$user) 
        { 
            http_response_code(400); 
            echo json_encode(['errors' => ['Token inválido o expirado']]); 
            exit; 
        } 
        $hash = password_hash($new_password, PASSWORD_BCRYPT); 
        $stmt = $pdo->prepare('UPDATE users SET password_hash = :p, reset_token = NULL, reset_token_expires = NULL WHERE id = :id'); 
        $stmt->execute(['p'=>$hash, 'id'=>$user['id']]); 
        echo json_encode(['success'=>true]); 
    } 
    catch (PDOException $e) 
    { 
        http_response_code(500); 
        echo json_encode(['errors' => ['Error del servidor']]); 
    } 
?>