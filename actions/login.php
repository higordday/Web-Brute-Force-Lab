<?php

if (!isset($_POST['submit_button']))
{

    echo json_encode(array('status' => false, 'message' => 'The form was not sent')); return; exit;

}

session_start();

$credentials = array('login' => $_POST['login'], 'password' => $_POST['password']);

if ((empty($credentials['login'])) || (empty($credentials['password']))) 
{

    $_SESSION['login_form_failure'] = 'Enter the authentication credentials'; header('Location: /'); return;

}

# -

$authentication = array('login' => 'admin', 'password' => '$2y$10$Gg0hn9GO0Yd994M1qIMSpeD2MGKsB/dNHLZFNTUr7X.cjs4pSajK.');

# -

if (strtolower($credentials['login']) != $authentication['login']) 
{

    $_SESSION['login_form_failure'] = 'Invalid Login'; header('Location: /'); return;

}

if (!password_verify($credentials['password'], $authentication['password'])) 
{

    $_SESSION['login_form_failure'] = 'Invalid Password'; header('Location: /'); return;

}

echo '<p>Login Successful</p>';