<?php 
    declare(strict_types=1); 
    session_start(); 
    ini_set('session.cookie_httponly', '1'); 
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') 
    { 
        ini_set('session.cookie_secure', '1'); 
    } 
    define('BASE_PATH', __DIR__); 
    define('DB_HOST', 'localhost'); 
    define('DB_USER', 'root'); 
    define('DB_PASS', '123admin@_'); 
    define('DB_NAME', 'karnak'); 
    function dbConnect(): PDO 
    { 
        return new PDO( 'mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4', DB_USER, DB_PASS, [ PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, ] ); 
    } 
    function redirectIfLoggedIn(string $redirectTo = 'dashboard.php'): void 
    { 
        if (isset($_SESSION['user_id'])) 
        { 
            header('Location: '.$redirectTo); exit; 
        } 
    } 
    function sessionInit(): void 
    { 
        $timeout = 15 * 60; 
        if (isset($_SESSION['LAST_ACTIVITY']) && (time() - $_SESSION['LAST_ACTIVITY'] > $timeout)) 
        { 
            session_destroy(); 
            session_start(); 
        } 
        $_SESSION['LAST_ACTIVITY'] = time(); 
        if (!isset($_SESSION['user_id']) && isset($_COOKIE['remember_me_token']) && isset($_COOKIE['remember_me_user'])) 
        { 
            try 
            { 
                $pdo = dbConnect(); 
                $stmt = $pdo->prepare('SELECT id, username FROM users WHERE id = :id AND remember_token = :tok'); 
                $stmt->execute(['id' => (int)$_COOKIE['remember_me_user'], 'tok' => $_COOKIE['remember_me_token']]); 
                $row = $stmt->fetch(); 
                if ($row) 
                { 
                    $_SESSION['user_id'] = (int)$row['id']; $_SESSION['username'] = $row['username']; $_SESSION['LAST_ACTIVITY'] = time(); 
                } 
            } 
            catch (PDOException $e) { } 
        } 
    } 
    register_shutdown_function(function(){}); 
    sessionInit(); 
?>