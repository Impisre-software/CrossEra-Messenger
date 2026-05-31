<?php
ob_start();
session_start();

$adminID = 'admin'; 
$rDir = 'rooms/';
$up = 'uploads/';
$avatarDir = 'avatars/';
$modDir = 'mods/';           
$modQueueDir = 'mods_queue/'; 
$reacDir = 'reacs/';  

foreach([$rDir, $up, $avatarDir, $modDir, $modQueueDir, $reacDir] as $dir) {
    if(!is_dir($dir)) @mkdir($dir, 0777);
}

if (!file_exists('config.php')) {
    $k = bin2hex(openssl_random_pseudo_bytes(16));
    file_put_contents('config.php', "<?php \$crypto_key = '$k'; ?>");
}
require_once('config.php');

$passF = $rDir . 'users_pass.db.php';
$groupsF = $rDir . 'groups_list.db.php';
$onlineF = $rDir . 'online.db.php';
$unreadF = $rDir . 'unread_tracker.db.php';

$myU = $_SESSION['ce_uid'] ?? '';
$myN = $_SESSION['ce_nick'] ?? '';

if($myU && !$myN) $myN = $myU;

$myContactsF = $rDir . "contacts_" . $myU . ".db.php";
$userModsFile = $rDir . "mods_user_" . $myU . ".db.php";

$theme = $_COOKIE['ce_theme'] ?? 'light';
if(isset($_GET['toggle_theme']) && $myU) {
    $theme = ($theme == 'dark') ? 'light' : 'dark';
    setcookie('ce_theme', $theme, time() + (86400 * 30), "/");
    header("Location: " . $_SERVER['HTTP_REFERER']); exit;
}

if($myU) {
    $onlines = file_exists($onlineF) ? file($onlineF) : [];
    $newOnlines = ["<?php die(); ?>\n"];
    foreach($onlines as $ol) {
        if(strpos($ol, '<?php') !== false || !trim($ol)) continue;
        $od = explode('|', trim($ol));
        if(($od[0] ?? '') != $myU && ($od[1] ?? 0) > (time() - 300)) $newOnlines[] = trim($ol) . "\n";
    }
    $newOnlines[] = "$myU|" . time() . "\n";
    file_put_contents($onlineF, implode("", $newOnlines), LOCK_EX);
}

function db_append($f, $d) {
    if(!file_exists($f)) file_put_contents($f, "<?php die(); ?>\n");
    return file_put_contents($f, $d . "\n", FILE_APPEND | LOCK_EX);
}

function v_crypt($d, $k, $mode = 'enc') {
    if ($mode == 'enc') {
        $iv = openssl_random_pseudo_bytes(16);
        $salt = openssl_random_pseudo_bytes(16);
        $msg_key = hash_hmac('sha256', $salt, $k, true);
        $msg_key = substr($msg_key, 0, 16); 
        $enc = openssl_encrypt($d, "aes-128-ctr", $msg_key, 0, $iv);
        return "B:" . str_replace(['+','/','='], ['-','_',''], base64_encode($iv . "::" . $salt . "::" . $enc));
    } else {
        if (substr($d, 0, 2) !== "A:" && substr($d, 0, 2) !== "B:") return $d;
        
        if (substr($d, 0, 2) === "A:") {
            $raw = base64_decode(str_replace(['-','_'], ['+','/'], substr($d, 2)));
            $p = explode("::", $raw);
            return openssl_decrypt($p[1] ?? '', "aes-128-ctr", $k, 0, $p[0] ?? '');
        }
        
        $raw = base64_decode(str_replace(['-','_'], ['+','/'], substr($d, 2)));
        $p = explode("::", $raw);
        
        $iv = $p[0] ?? '';
        $salt = $p[1] ?? '';
        $enc = $p[2] ?? '';
        
        $msg_key = hash_hmac('sha256', $salt, $k, true);
        $msg_key = substr($msg_key, 0, 16);
        return openssl_decrypt($enc, "aes-128-ctr", $msg_key, 0, $iv);
    }
}

function is_user_online($u) {
    global $onlineF;
    if(!file_exists($onlineF)) return false;
    foreach(file($onlineF) as $ol) {
        if(strpos($ol, '<?php') !== false) continue;
        $od = explode('|', trim($ol));
        if(($od[0] ?? '') == $u && ($od[1] ?? 0) > (time() - 300)) return true;
    }
    return false;
}

function get_avatar_html($u, $name) {
    global $avatarDir;
    $f = $avatarDir . md5($u) . '.png';
    $isOnline = is_user_online($u);
    $onlineBadge = $isOnline ? "<span style='position:absolute; bottom:-2px; right:-2px; width:8px; height:8px; background:#2aa198; border:2px solid white; border-radius:50%;' title='В сети'></span>" : "";
    
    $html = "<div style='position:relative; display:inline-block; vertical-align:middle; margin-right:5px;'>";
    if(file_exists($f)) {
        $html .= "<img src='$f?".filemtime($f)."' width='24' height='24' style='border-radius:50%; display:block;'>";
    } else {
        $colors = ['#268bd2', '#b58900', '#cb4b16', '#dc322f', '#2aa198'];
        $c = $colors[abs(crc32($u)) % count($colors)];
        $l = mb_strtoupper(mb_substr($name ?? 'U', 0, 1));
        $html .= "<div style='width:24px; height:24px; border-radius:50%; background:$c; color:white; text-align:center; line-height:24px; font-size:10px;'>$l</div>";
    }
    return $html . $onlineBadge . "</div>";
}

function parse_msg($m) {
    $m = htmlspecialchars($m);
    $smiles = [
        ':heart:' => 'heart.gif', ':hi:' => 'hi.gif', ':sarcasm:' => 'sarcasm.gif',
        ':cool:' => 'good.gif', ':smile:' => 'smile.gif', ':fire:' => 'fire.gif', ':laugh:' => 'smech.gif'
    ];
    foreach($smiles as $code => $img) {
        $m = str_replace($code, "<img src='smiles/$img' width='18' height='18' style='vertical-align:middle;' title='$code'>", $m);
    }
    $m = preg_replace('/\[img\](.*?)\[\/img\]/', '<br><img src="$1" style="max-width:100%; border-radius:5px; margin-top:5px;">', $m);
    $m = preg_replace('/\[file\](.*?)\[\/file\]/', '<br><a href="$1" style="display:inline-block; background:#eee; padding:4px; border:1px solid #777; text-decoration:none; color:#333; font-size:10px;">📁 Файл</a>', $m);
    return nl2br($m);
}

function get_last_view_time($u, $target) {
    global $unreadF; if(!file_exists($unreadF)) return 0;
    foreach(file($unreadF) as $l) {
        if(strpos($l, '<?php') !== false) continue;
        $d = explode('|', trim($l));
        if(($d[0] ?? '') == $u && ($d[1] ?? '') == $target) return (int)($d[2] ?? 0);
    }
    return 0;
}

function set_last_view_time($u, $target) {
    global $unreadF; $lines = file_exists($unreadF) ? file($unreadF) : [];
    $newLines = ["<?php die(); ?>\n"];
    foreach($lines as $l) {
        if(strpos($l, '<?php') !== false || !trim($l)) continue;
        $d = explode('|', trim($l));
        if(($d[0] ?? '') != $u || ($d[1] ?? '') != $target) $newLines[] = trim($l) . "\n";
    }
    $newLines[] = "$u|$target|" . time() . "\n";
    file_put_contents($unreadF, implode("", $newLines), LOCK_EX);
}

function has_new_messages($u, $target, $file_path) {
    if(!file_exists($file_path)) return false;
    $last_view = get_last_view_time($u, $target);
    $lines = file($file_path);
    foreach($lines as $l) {
        if(strpos($l, '<?php') !== false || !trim($l)) continue;
        $d = explode('|', trim($l));
        if(($d[3] ?? '') != $u && filemtime($file_path) > $last_view) return true;
    }
    return false;
}

$to = preg_replace('/[^a-z0-9_]/', '', $_REQUEST['to'] ?? 'all');
if($to == 'saved') $to = "saved_" . $myU;

$curF = $rDir . (strpos($to, 'pm_') === 0 || strpos($to, 'saved_') === 0 || strpos($to, 'group_') === 0 ? "$to.db.php" : "room_$to.db.php");
if($to == 'all') $curF = $rDir . "global.db.php";

$view = $_GET['view'] ?? 'chat';
if($myU && $view == 'chat') { set_last_view_time($myU, $to); }

if(isset($_GET['del_msg']) && $myU) {
    $target_mid = $_GET['del_msg'];
    if(file_exists($curF)) {
        $lines = file($curF); $newLines = [];
        foreach($lines as $l) {
            if(strpos($l, '<?php') !== false) { $newLines[] = $l; continue; }
            if(md5(trim($l)) == $target_mid) {
                $d = explode('|', trim($l));
                if(($d[3] ?? '') == $myU || $myU == $adminID) {
                    $newLines[] = "{$d[0]}|" . v_crypt("[Сообщение удалено]", $crypto_key) . "|{$d[2]}|{$d[3]}\n";
                    continue;
                }
            }
            $newLines[] = $l;
        }
        file_put_contents($curF, implode("", $newLines), LOCK_EX);
    }
    header("Location: ?view=chat&to=$to"); exit;
}

if(isset($_GET['add_reac']) && $myU) {
    $mid = preg_replace('/[^a-z0-9]/', '', $_GET['mid']); 
    $type = preg_replace('/[^a-z0-9\.]/', '', $_GET['type']); 
    $rf = $reacDir . $mid . ".db.php";
    $already = false;
    if(file_exists($rf)) {
        foreach(file($rf) as $line) { if(strpos($line, "$myU|$type") !== false) $already = true; }
    }
    if(!$already) db_append($rf, "$myU|$myN|$type");
    header("Location: " . $_SERVER['HTTP_REFERER']); exit;
}

if(isset($_GET['add_c']) && $myU) {
    $cid = preg_replace('/[^a-z0-9]/', '', $_GET['add_c']);
    $cn = htmlspecialchars($_GET['n']);
    if($cid != $myU) db_append($myContactsF, "$cid|$cn");
    header("Location: ?view=contacts"); exit;
}

// ЗАГРУЗКА АВАТАРОК С ПРОВЕРКОЙ GETIMAGESIZE()
if(isset($_POST['up_ava']) && $myU){
    if(!empty($_FILES['ava_file']['tmp_name'])) {
        $check = @getimagesize($_FILES['ava_file']['tmp_name']);
        if($check !== false) {
            move_uploaded_file($_FILES['ava_file']['tmp_name'], $avatarDir . md5($myU) . '.png');
            header("Location: ?view=profile"); exit;
        } else {
            $_SESSION['ce_error'] = "Ошибка: Файл не является настоящим изображением!";
            header("Location: ?view=profile"); exit;
        }
    }
}

if (isset($_POST['create_room']) && $myU) {
    $name = htmlspecialchars($_POST['r_name']); $type = $_POST['r_type']; 
    $id = bin2hex(openssl_random_pseudo_bytes(4));
    db_append($groupsF, "$id|$name|$type|$myU");
    header("Location: ?view=groups"); exit;
}

$myEnabledMods = [];
if($myU && file_exists($userModsFile)) {
    foreach(file($userModsFile) as $l) { if(strpos($l, '<?php') === false && trim($l)) $myEnabledMods[] = trim($l); }
}

if(isset($_GET['toggle_my_mod']) && $myU) {
    $m = basename($_GET['toggle_my_mod']);
    $m = preg_replace('/[^a-zA-Z0-9_]/', '', $m);
    if(in_array($m, $myEnabledMods)) $myEnabledMods = array_diff($myEnabledMods, [$m]);
    else if(file_exists($modDir . $m . ".php")) $myEnabledMods[] = $m;
    file_put_contents($userModsFile, "<?php die(); ?>\n" . implode("\n", array_unique($myEnabledMods)));
    header("Location: ?view=mod_store"); exit;
}

if(isset($_POST['login'])){
    $u = strtolower(preg_replace('/[^a-z0-9]/', '', $_POST['u_id']));
    $p = $_POST['pwd'] ?? ''; $n = htmlspecialchars($_POST['dn'] ?? $u);
    if($u && $p){
        $exists = false; $auth = false;
        if(file_exists($passF)) {
            foreach(file($passF) as $l) {
                $d = explode('|', trim($l));
                if(($d[0] ?? '') == $u) { $exists = true; if(password_verify($p, $d[1])) $auth = true; break; }
            }
        }
        if($auth || !$exists) {
            if(!$exists) db_append($passF, "$u|".password_hash($p, PASSWORD_DEFAULT)."|$n");
            $_SESSION['ce_uid'] = $u; $_SESSION['ce_nick'] = $n;
            header("Location: index.php"); exit;
        } else {
            $_SESSION['ce_error'] = "Неверный пароль для этого ID!";
        }
    }
}

if(isset($_GET['logout'])){ session_destroy(); header("Location: index.php"); exit; }

// ОТПРАВКА СООБЩЕНИЙ С КОМБИНИРОВАННОЙ ПРОВЕРКОЙ КАРТИНОК
if($myU && isset($_POST['send_msg'])){
    $m = $_POST['msg'] ?? ''; $fT = "";
    $isValidFile = true;

    if(!empty($_FILES['f']['name'])){
        $ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));
        $isImageExt = in_array($ext, ['jpg','png','gif','jpeg']);
        
        if($isImageExt) {
            $check = @getimagesize($_FILES['f']['tmp_name']);
            if($check === false) {
                $isValidFile = false;
                $_SESSION['ce_error'] = "Атака заблокирована: Файл маскируется под картинку!";
            }
        }

        if($isValidFile) {
            $nf = bin2hex(openssl_random_pseudo_bytes(5)).'.'.$ext;
            if(move_uploaded_file($_FILES['f']['tmp_name'], $up.$nf)) {
                $fT = $isImageExt ? "[img]".$up.$nf."[/img]" : "[file]".$up.$nf."[/file]";
            }
        }
    }
    
    if(($m || $fT) && $isValidFile) {
        db_append($curF, "$myN|".v_crypt($m.($m&&$fT?" ":"").$fT, $crypto_key)."|".date('H:i')."|$myU");
    }
    header("Location: ?view=$view&to=$to"); exit;
}
 
$has_global_new = has_new_messages($myU, 'all', $rDir . 'global.db.php');

// Вытаскиваем ошибку из сессии, если она там есть
$sys_error = $_SESSION['ce_error'] ?? '';
unset($_SESSION['ce_error']);
?>
<!DOCTYPE html>
<html>
<head>
    <link rel="icon" type="image/png" href="favicon.png">   
    <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CrossEra Hybrid</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        html, body { height:100%; width:100%; overflow:hidden; }
        
        body.theme-light { background:#000; color:#839496; }
        body.theme-light .box { background:#eee8d5; color:#073642; }
        body.theme-light #chat, body.theme-light .main-panel { background:#fff; color:#333; }
        body.theme-light .m { border-bottom:1px solid #eee; }
        body.theme-light .mod-card { background:#fff; border:1px solid #ccc; }
        
        body.theme-dark { background:#111; color:#eee; }
        body.theme-dark .box { background:#1e1e1e; color:#ddd; }
        body.theme-dark #chat, body.theme-dark .main-panel { background:#121212; color:#fff; }
        body.theme-dark .m { border-bottom:1px solid #222; }
        body.theme-dark .mod-card { background:#1a1a1a; border:1px solid #333; }
        body.theme-dark textarea { background:#252525; color:#fff; border:1px solid #444; }

        body { font-family:sans-serif; font-size:12px; }
        .box { height:100%; width:100%; display:flex; flex-direction:column; overflow:hidden; }
        .hdr { background:#a01ae8; color:white; padding:10px; font-weight:bold; display:flex; justify-content:space-between; align-items:center; flex-shrink:0; }
        .nav { background:#93a1a1; padding:5px; display:flex; flex-wrap:wrap; gap:3px; border-bottom:1px solid #586e75; flex-shrink:0; }
        body.theme-dark .nav { background:#2d2d2d; border-bottom:1px solid #444; }
        .nav a { background:#eee; color:#000; text-decoration:none; padding:4px 8px; font-size:10px; border:1px solid #666; border-radius:3px; }
        .nav a.active { background:#2aa198; color:white; }
        .nav .unread-dot { color:#dc322f; font-weight:bold; font-size:9px; }
        .content { flex:1; display:flex; flex-direction:column; overflow:hidden; min-height:0; }
        #chat, .main-panel { flex:1; overflow-y:auto; padding:10px; }
        .m { padding:8px 0; position:relative; }
        .btn { background:#2aa198; color:white; border:none; padding:6px 12px; cursor:pointer; text-decoration:none; font-size:11px; border-radius:3px; display:inline-block; }
        .mod-card { padding:10px; margin-bottom:8px; border-radius:5px; }
        .reac-bar { margin-left:29px; margin-top:4px; display:flex; gap:3px; align-items:center; }
        .reac-btn { background:#f0f0f0; border:1px solid #ccc; border-radius:10px; padding:1px 4px; font-size:9px; text-decoration:none; color:#333; }
        body.theme-dark .reac-btn { background:#2a2a2a; border:1px solid #444; color:#ccc; }
        .reac-menu { display:none; position:absolute; background:white; border:1px solid #333; padding:5px; z-index:10; border-radius:5px; bottom:20px; }
        body.theme-dark .reac-menu { background:#222; border-color:#555; }
        .del-link { color:#dc322f; text-decoration:none; margin-left:8px; font-size:10px; font-weight:bold; }
        .err-msg { background:#dc322f; color:white; padding:8px; margin-bottom:10px; border-radius:3px; text-align:center; font-weight:bold; }
    </style>
</head>
<body class="theme-<?php echo $theme; ?>">
<div class="box">
    <?php if(!$myU): ?>
        <div class="hdr">
            <div style="display:flex; align-items:center;">
                <div style="width:24px; height:24px; border-radius:50%; background:#586e75; color:white; text-align:center; line-height:24px; font-size:10px;">G</div>
                <span style="margin-left:5px; color:white;">Гость (Вход в систему)</span>
            </div>
            <span style="font-size:10px; opacity:0.8;">CrossEra v1.0 Hybrid</span>
        </div>

        <div class="nav">
            <a href="#" class="active">Главная / Инфо</a>
            <a href="#auth-section">Авторизация</a>
        </div>

        <div class="content" style="overflow-y:auto;">
            <div class="main-panel" style="line-height:1.6;">
                
                <div style="text-align:center; margin-bottom:15px; background:#fff; padding:10px; border-radius:5px; border:1px solid rgba(0,0,0,0.1);">
                    <img src="кросс-платформеность.png" alt="CrossEra на девайсах" style="max-width:100%; height:auto; border-radius:3px;">
                </div>

                <div style="background:#a01ae8; color:white; padding:10px; margin-bottom:15px; font-size:11px; border-radius:3px; text-align:center; font-weight:bold;">
                    Impisre Software представляет: кросс-платформенный защищённый мессенджер CrossEra.
                </div>

                <?php if($sys_error): ?>
                    <div class="err-msg"><?php echo $sys_error; ?></div>
                <?php endif; ?>

                <h3>Возможности системы:</h3><br>

                <div class="mod-card">
                    <b>Защита AES-128 шифрованием</b>
                    <p style="font-size:11px; opacity:0.8; margin-top:4px;">Шифрование текстовых пакетов на сервере. Ваши файлы баз данных защищены от прямого чтения злоумышленниками.</p>
                </div>

                <div class="mod-card">
                    <b>Кросс-платформенность</b>
                    <p style="font-size:11px; opacity:0.8; margin-top:4px;">Полноценная работа на ретро-смартфонах (Symbian S60v5, Windows Mobile 6.x), КПК, старых ПК под Windows и любых современных смартфонах.</p>
                </div>

                <div class="mod-card">
                    <b>Мод-система</b>
                    <p style="font-size:11px; opacity:0.8; margin-top:4px;">Прямая динамическая кастомизация. Возможность подключать и расширять исполняемую логику приложения через персональный репозиторий модулей.</p>
                </div>

                <div class="mod-card">
                    <b>Темы оформления и Статусы</b>
                    <p style="font-size:11px; opacity:0.8; margin-top:4px;">Индикация нахождения пользователей в сети в реальном времени, а также поддержка легкого и ночного режимов для снижения нагрузки на глаза.</p>
                </div>

                <hr style="margin:20px 0; opacity:0.2;">
                <h3 id="auth-section" style="text-align:center;">Вход / Быстрая регистрация</h3><br>
                
                <div class="mod-card" style="max-width:320px; margin:0 auto; padding:15px;">
                    <form method="POST">
                        <label style="font-size:10px; display:block; margin-bottom:2px;">ID пользователя (только латиница):</label>
                        <input name="u_id" required style="width:100%; padding:6px; margin-bottom:8px; border-radius:3px; border:1px solid #777;"><br>
                        
                        <label style="font-size:10px; display:block; margin-bottom:2px;">Никнейм (отображаемое имя):</label>
                        <input name="dn" style="width:100%; padding:6px; margin-bottom:8px; border-radius:3px; border:1px solid #777;"><br>
                        
                        <label style="font-size:10px; display:block; margin-bottom:2px;">Пароль:</label>
                        <input name="pwd" type="password" required style="width:100%; padding:6px; margin-bottom:12px; border-radius:3px; border:1px solid #777;"><br>
                        
                        <input type="submit" name="login" value="ПОДКЛЮЧИТЬСЯ И ВОЙТИ" class="btn" style="width:100%; font-weight:bold; background:#a01ae8;">
                    </form>
                    <p style="font-size:9px; color:#777; text-align:center; margin-top:8px;">* Если указанный ID свободен, регистрация произойдет автоматически.</p>
                </div>

                <div style="text-align:center; font-size:10px; color:#976; margin-top:40px;">&copy; <?php echo date('Y'); ?> Impisre Software</div>
            </div>
        </div>
    <?php else: ?>
        <div class="hdr">
            <a href="?view=profile" style="color:white; text-decoration:none; display:flex; align-items:center;">
                <?php echo get_avatar_html($myU, $myN); ?> <span style="margin-left:5px;"><?php echo $myN; ?></span>
            </a>
            <a href="?logout=1" style="color:white; font-size:10px; text-decoration:none;">[Выход]</a>
        </div>

        <div class="nav">
            <a href="?view=chat&to=all" class="<?php echo ($to=='all')?'active':''; ?>"> Чат <?php echo $has_global_new ? '<span class="unread-dot">●</span>':''; ?></a>
            <a href="?view=groups" class="<?php echo ($view=='groups')?'active':''; ?>"> Группы</a>
            <a href="?view=contacts" class="<?php echo ($view=='contacts')?'active':''; ?>">Контакты</a>
            <a href="?view=chat&to=saved" class="<?php echo ($to=='saved_'.$myU || $to=='saved')?'active':''; ?>">Избр.</a>
            <a href="?view=mod_store" class="<?php echo ($view=='mod_store')?'active':''; ?>">Моды</a>
            <a href="?view=info" class="<?php echo ($view=='info')?'active':''; ?>">Инфа</a>
            <?php foreach($myEnabledMods as $m): ?>
                <a href="?view=run_<?php echo $m; ?>" style="background:#b58900; color:#fff;">модуль <?php echo substr($m,0,4); ?></a>
            <?php endforeach; ?>
        </div>

        <div class="content">
            <?php if($view == 'info'): ?>
                <div class="main-panel" style="line-height:1.6;">
                    <div style="background:#a01ae8; color:white; padding:10px; margin-bottom:15px; font-size:11px; border-radius:3px;">
                        <strong>Impisre Software</strong> представляет: кросс-платформенный защищённый мессенджер.
                    </div>
                    <h3> Возможности</h3>
                    <ul>
                        <li><b>AES-128 (from openSSL):</b> шифрование текстов на сервере.</li>
                        <li><b>Кросс-платформеность:</b> работа на S60v5, Windows Mobile 6.1, на ПК и десктопах.</li>
                        <li><b>Мод-система:</b> Прямая кастомизация и расширение логики приложения.</li>
                        <li><b>Статусы и Темы:</b> трекинг онлайна и ночной режим.</li>
                    </ul>
                    <div style="text-align:center; font-size:10px; color:#976; margin-top:30px;">&copy; <?php echo date('Y'); ?> Impisre Software</div>
                </div>

            <?php elseif($view == 'chat'): ?>
                <?php if($sys_error): ?>
                    <div class="err-msg" style="margin: 5px;"><?php echo $sys_error; ?></div>
                <?php endif; ?>

                <div id="chat">
                    <?php if(file_exists($curF)) {
                        $lines = file($curF);
                        foreach($lines as $idx => $l) {
                            if(strpos($l, '<?php') !== false || !trim($l)) continue;
                            $d = explode('|', trim($l)); if(count($d) < 3) continue; 
                            $uid = $d[3] ?? ''; $msgID = md5(trim($l));
                            $plainMsg = v_crypt($d[1], $crypto_key, 'dec');
                            ?>
                            <div class="m">
                                <?php echo get_avatar_html($uid, $d[0]); ?>
                                <b><?php echo $d[0]; ?></b>
                                <?php if($uid && $uid != $myU): ?>
                                    <a href="?add_c=<?php echo $uid; ?>&n=<?php echo urlencode($d[0]); ?>" style="font-size:9px; color:#2aa198; text-decoration:none; border:1px solid; padding:0 2px; margin-left:4px;">+контакт</a>
                                <?php endif; ?>
                                
                                <small style="float:right; opacity:0.5;">
                                    <?php echo $d[2]; ?>
                                    <?php if(($uid == $myU || $myU == $adminID) && $plainMsg !== "[Сообщение удалено]"): ?>
                                        <a href="?del_msg=<?php echo $msgID; ?>&to=<?php echo $to; ?>" class="del-link" title="Удалить сообщение">[×]</a>
                                    <?php endif; ?>
                                </small><br>
                                
                                <div style="margin-left:29px;"><?php echo parse_msg($plainMsg); ?></div>
                                <div class="reac-bar">
                                    <?php 
                                    $rf = $reacDir . $msgID . ".db.php";
                                    if(file_exists($rf)) {
                                        $rcs = file($rf); $counts = [];
                                        foreach($rcs as $rl) {
                                            if(strpos($rl, '<?php') !== false) continue;
                                            $d_r = explode('|', trim($rl));
                                            if(isset($d_r[2])) $counts[$d_r[2]] = ($counts[$d_r[2]] ?? 0) + 1;
                                        }
                                        foreach($counts as $img => $count) echo "<span class='reac-btn'><img src='smiles/$img' width='12'> $count</span>";
                                    }
                                    ?>
                                    <a href="#" onclick="document.getElementById('rm<?php echo $idx;?>').style.display='block'; return false;" class="reac-btn">+</a>
                                    <div id="rm<?php echo $idx;?>" class="reac-menu">
                                        <?php foreach(['fire.gif','smile.gif','good.gif','heart.gif'] as $t) echo "<a href='?add_reac=1&mid=$msgID&type=$t&to=$to'><img src='smiles/$t' width='20'></a> "; ?>
                                        <a href="#" onclick="this.parentElement.style.display='none'; return false;" style="color:red;">&times;</a>
                                    </div>
                                </div>
                            </div>
                        <?php }
                    } ?>
                </div>
                <form method="POST" enctype="multipart/form-data" style="padding:8px; background:rgba(0,0,0,0.05); border-top:1px solid rgba(0,0,0,0.1); flex-shrink:0;">
                    <textarea name="msg" style="width:100%; height:40px; border-radius:3px; padding:5px;" placeholder="Сообщение..."></textarea>
                    <div style="margin-top:5px; display:flex; justify-content:space-between; align-items:center;">
                        <input type="file" name="f" style="font-size:10px; width:60%;">
                        <input type="submit" name="send_msg" value=">>" class="btn">
                    </div>
                </form>

            <?php elseif($view == 'contacts'): ?>
                <div class="main-panel">
                    <h3>Мои контакты</h3><br>
                    <?php if(file_exists($myContactsF)): 
                        foreach(file($myContactsF) as $l): if(strpos($l,'<?php')!==false || !trim($l))continue; $c=explode('|',trim($l)); 
                        $pm = ($myU < $c[0]) ? "pm_{$myU}_{$c[0]}" : "pm_{$c[0]}_{$myU}"; 
                        $has_pm_unread = has_new_messages($myU, $pm, $rDir . $pm . ".db.php");
                        ?>
                        <div class="mod-card">
                            <?php echo get_avatar_html($c[0], $c[1]); ?> 
                            <b><?php echo $c[1]; ?></b> 
                            <?php echo $has_pm_unread ? '<span style="color:#dc322f; font-size:10px;">(НОВОЕ)</span>':''; ?>
                            <a href="?view=chat&to=<?php echo $pm; ?>" class="btn" style="float:right;">Чат</a>
                        </div>
                    <?php endforeach; else: echo "Список пуст"; endif; ?>
                </div>

            <?php elseif($view == 'profile'): ?>
                <div class="main-panel" style="text-align:center;">
                    <h3>Настройки профиля</h3><br>
                    
                    <?php if($sys_error): ?>
                        <div class="err-msg"><?php echo $sys_error; ?></div>
                    <?php endif; ?>

                    <?php echo get_avatar_html($myU, $myN); ?><br><br><b><?php echo $myN; ?></b><hr style="margin:15px 0; opacity:0.2;">
                    
                    <form method="POST" enctype="multipart/form-data">
                        <label style="font-size:11px; display:block; margin-bottom:5px;">Сменить аватар:</label>
                        <input type="file" name="ava_file"><br><br>
                        <input type="submit" name="up_ava" value="Обновить" class="btn">
                    </form>
                    
                    <hr style="margin:20px 0; opacity:0.2;">
                    <p>Текущая тема: <b><?php echo ($theme == 'dark') ? 'Тёмная ' : 'Светлая '; ?></b></p><br>
                    <a href="?toggle_theme=1" class="btn" style="background:#586e75;">Переключить тему оформления</a>
                </div>

            <?php elseif($view == 'groups'): ?>
                <div class="main-panel">
                    <h3>Каналы и Группы</h3><br>
                    <form method="POST" style="background:rgba(0,0,0,0.05); padding:10px; border-radius:5px; margin-bottom:15px;">
                        <input name="r_name" required placeholder="Название" style="padding:4px;">
                        <select name="r_type" style="padding:3px;"><option value="group">Группа</option><option value="channel">Канал</option></select>
                        <input type="submit" name="create_room" value="+" class="btn" style="padding:4px 10px;">
                    </form>
                    <?php if(file_exists($groupsF)) foreach(file($groupsF) as $l): if(strpos($l,'<?php')!==false || !trim($l))continue; $g=explode('|',trim($l)); 
                        $g_target = "group_" . $g[0];
                        $has_g_unread = has_new_messages($myU, $g_target, $rDir . $g_target . ".db.php");
                        ?>
                        <div class="mod-card">
                            <b><?php echo ($g[2]=='channel'?'канал':'группа'); ?> <?php echo $g[1]; ?></b> 
                            <?php echo $has_g_unread ? '<span style="color:#dc322f; font-size:10px;">(НОВОЕ)</span>':''; ?>
                            <a href="?view=chat&to=<?php echo $g_target; ?>" class="btn" style="float:right;">Войти</a>
                        </div>
                    <?php endforeach; ?>
                </div>

            <?php elseif($view == 'mod_store'): ?>
                <div class="main-panel">
                    <h3>Магазин расширений</h3><br>
                    <?php foreach(glob($modDir."*.php") as $f): $fn=basename($f,'.php'); $inst=in_array($fn,$myEnabledMods); ?>
                        <div class="mod-card">модуль-<?php echo $fn; ?><a href="?toggle_my_mod=<?php echo $fn; ?>" class="btn" style="float:right; background:<?php echo $inst?'#dc322f':'#2aa198';?>"><?php echo $inst?'Удалить':'Ставить';?></a></div>
                    <?php endforeach; ?>
                </div>

            <?php elseif(strpos($view, 'run_') === 0): ?>
                <div class="main-panel">
                    <?php 
                    $mName = str_replace('run_', '', $view); 
                    $mName = preg_replace('/[^a-zA-Z0-9_]/', '', $mName);
                    // Проверяем, куплен/разрешен ли модуль текущему пользователю или это админ
                    if(!empty($mName) && file_exists($modDir.$mName.".php") && (in_array($mName, $myEnabledMods) || $myU == $adminID)){ 
                        include_once($modDir.$mName.".php"); 
                        $f = "mod_".$mName."_main"; 
                        if(function_exists($f)) $f($myU, $adminID); 
                    } else {
                        echo "<b style='color:red;'>Доступ к модулю заблокирован. Активируйте его в магазине!</b>";
                    }
                    ?>
                </div>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>
<script>var c=document.getElementById('chat');if(c)c.scrollTop=c.scrollHeight;</script>
</body>
</html>
