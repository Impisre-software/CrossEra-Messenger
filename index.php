<?php
ob_start();
session_start();

$adminID = 'admin'; 
$rDir = 'rooms/';
$up = 'uploads/';
$avatarDir = 'avatars/';
$modDir = 'mods/';           
$reacDir = 'reacs/';  
$viewsDir = 'views_counter/';

foreach([$rDir, $up, $avatarDir, $modDir, $reacDir, $viewsDir] as $dir) {
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
$reqF = $rDir . 'contact_requests.db.php';

$myU = $_SESSION['ce_uid'] ?? '';
$myN = $_SESSION['ce_nick'] ?? '';

$theme = $_COOKIE['ce_theme'] ?? 'light';
if(isset($_GET['toggle_theme']) && $myU) {
    $theme = ($theme == 'dark') ? 'light' : 'dark';
    setcookie('ce_theme', $theme, time() + (86400 * 30), "/");
    header("Location: " . ($_SERVER['HTTP_REFERER'] ?? 'index.php')); exit;
}

// Запись онлайна
if($myU) {
    $onlines = file_exists($onlineF) ? file($onlineF) : [];
    $newOnlines = ["<?php die(); ?>\n"];
    foreach($onlines as $ol) {
        if(strpos($ol, '<?php') !== false || !trim($ol)) continue;
        $od = explode('|', trim($ol));
        if(($od[0] ?? '') != $myU && ($od[1] ?? 0) > (time() - 300)) {
            $newOnlines[] = rtrim(trim($ol), "\r\n") . "\n";
        }
    }
    $newOnlines[] = "$myU|" . time() . "\n";
    file_put_contents($onlineF, implode("", $newOnlines), LOCK_EX);
}

// Функции безопасной работы с БД
function db_append($f, $d) {
    if(!file_exists($f)) file_put_contents($f, "<?php die(); ?>\n");
    $d = str_replace(["\r", "\n"], " ", $d);
    return file_put_contents($f, $d . "\n", FILE_APPEND | LOCK_EX);
}

function v_crypt($d, $k, $mode = 'enc') {
    if ($mode == 'enc') {
        $iv = openssl_random_pseudo_bytes(16);
        $salt = openssl_random_pseudo_bytes(16);
        $msg_key = substr(hash_hmac('sha256', $salt, $k, true), 0, 16); 
        $enc = openssl_encrypt($d, "aes-128-ctr", $msg_key, 0, $iv);
        return "B:" . str_replace(['+','/','='], ['-','_',''], base64_encode($iv . "::" . $salt . "::" . $enc));
    } else {
        if (substr($d, 0, 2) !== "B:") return $d;
        $raw = base64_decode(str_replace(['-','_'], ['+','/'], substr($d, 2)));
        $p = explode("::", $raw);
        $iv = $p[0] ?? ''; $salt = $p[1] ?? ''; $enc = $p[2] ?? '';
        $msg_key = substr(hash_hmac('sha256', $salt, $k, true), 0, 16);
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
        ':cool:' => 'good.gif', ':smile:' => 'smile.gif', ':fire:' => 'fire.gif',
        '(ツ)' => 'smile.gif', '¯\_(ツ)_/¯' => 'smile.gif'
    ];
    foreach($smiles as $code => $img) {
        $m = str_replace($code, "<img src='smiles/$img' width='18' height='18' style='vertical-align:middle;' title='$code'>", $m);
    }
    $m = preg_replace('/\[img\](uploads\/[a-z0-9]+\.(?:png|jpg|jpeg|gif))\[\/img\]/i', '<br><img src="$1" style="max-width:100%; border-radius:5px; margin-top:5px;">', $m);
    $m = preg_replace('/\[file\](uploads\/[a-z0-9]+\.[a-z0-9]+)\[\/file\]/i', '<br><a href="$1" style="display:inline-block; background:#eee; padding:4px; border:1px solid #777; text-decoration:none; color:#333; font-size:10px;">Файл</a>', $m);
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
        if(($d[0] ?? '') != $u || ($d[1] ?? '') != $target) $newLines[] = rtrim(trim($l), "\r\n") . "\n";
    }
    $newLines[] = "$u|$target|" . time() . "\n";
    file_put_contents($unreadF, implode("", $newLines), LOCK_EX);
}

function has_new_messages($u, $target, $file_path) {
    if(!file_exists($file_path)) return false;
    $last_view = get_last_view_time($u, $target);
    if(filemtime($file_path) <= $last_view) return false;
    $lines = file($file_path);
    foreach($lines as $l) {
        if(strpos($l, '<?php') !== false || !trim($l)) continue;
        $d = explode('|', trim($l));
        if(($d[3] ?? '') != $u) return true;
    }
    return false;
}

// Роутинг и входящие параметры
$to = preg_replace('/[^a-z0-9_]/', '', $_REQUEST['to'] ?? 'all');
if($to == 'saved' && $myU) $to = "saved_" . $myU;

$view = preg_replace('/[^a-z0-9_]/', '', $_GET['view'] ?? 'chat');

$curF = $rDir . (strpos($to, 'pm_') === 0 || strpos($to, 'saved_') === 0 || strpos($to, 'group_') === 0 || strpos($to, 'gb_') === 0 ? "$to.db.php" : "room_$to.db.php");
if($to == 'all') $curF = $rDir . "global.db.php";

if($myU && $view == 'chat') { set_last_view_time($myU, $to); }

// ФУНКЦИЯ ЭКСПОРТА В ТЕКСТ (TXT)
if(isset($_GET['export_txt']) && $myU && file_exists($curF)) {
    header('Content-Type: text/plain; charset=utf-8');
    header('Content-Disposition: attachment; filename="history_'.$to.'_'.date('Y-m-d').'.txt"');
    foreach(file($curF) as $l) {
        if(strpos($l, '<?php') !== false || !trim($l)) continue;
        $d = explode('|', trim($l));
        $plain = v_crypt($d[1], $crypto_key, 'dec');
        echo "[{$d[2]}] {$d[0]}: " . strip_tags(str_replace(['[img]','[/img]','[file]','[/file]'], ' ', $plain)) . "\r\n";
    }
    exit;
}

// УДАЛЕНИЕ СООБЩЕНИЯ
if(isset($_GET['del_msg']) && $myU) {
    $target_mid = preg_replace('/[^a-z0-9]/', '', $_GET['del_msg']);
    if(file_exists($curF)) {
        $lines = file($curF); $newLines = [];
        foreach($lines as $l) {
            if(strpos($l, '<?php') !== false) { $newLines[] = $l; continue; }
            if(md5(trim($l)) == $target_mid) {
                $d = explode('|', trim($l));
                if(($d[3] ?? '') == $myU || $myU == $adminID) {
                    $newLines[] = "{$d[0]}|" . v_crypt("[Сообщение удалено]", $crypto_key) . "|{$d[2]}|{$d[3]}|1\n";
                    continue;
                }
            }
            $newLines[] = $l;
        }
        file_put_contents($curF, implode("", $newLines), LOCK_EX);
    }
    header("Location: ?view=chat&to=$to"); exit;
}

// РЕДАКТИРОВАНИЕ СООБЩЕНИЯ
if(isset($_POST['edit_msg']) && $myU) {
    $target_mid = preg_replace('/[^a-z0-9]/', '', $_POST['mid']);
    $new_text = $_POST['new_text'] ?? '';
    if(file_exists($curF) && $new_text) {
        $lines = file($curF); $newLines = [];
        foreach($lines as $l) {
            if(strpos($l, '<?php') !== false) { $newLines[] = $l; continue; }
            if(md5(trim($l)) == $target_mid) {
                $d = explode('|', trim($l));
                if(($d[3] ?? '') == $myU) {
                    $newLines[] = "{$d[0]}|" . v_crypt($new_text, $crypto_key) . "|{$d[2]}|{$d[3]}|1\n";
                    continue;
                }
            }
            $newLines[] = $l;
        }
        file_put_contents($curF, implode("", $newLines), LOCK_EX);
    }
    header("Location: ?view=chat&to=$to"); exit;
}

// РЕАКЦИИ
if(isset($_GET['add_reac']) && $myU) {
    $mid = preg_replace('/[^a-z0-9]/', '', $_GET['add_reac']); 
    $type = preg_replace('/[^a-z0-9\.]/', '', $_GET['type']); 
    $rf = $reacDir . $mid . ".db.php";
    $already = false;
    if(file_exists($rf)) {
        foreach(file($rf) as $line) { if(strpos($line, "$myU|$type") !== false) $already = true; }
    }
    if(!$already) db_append($rf, "$myU|$myN|$type");
    header("Location: " . ($_SERVER['HTTP_REFERER'] ?? 'index.php')); exit;
}

// ОТПРАВКА ЗАЯВКИ В КОНТАКТЫ
if(isset($_GET['add_c']) && $myU) {
    $cid = preg_replace('/[^a-z0-9]/', '', $_GET['add_c']);
    if($cid != $myU) {
        $already = false;
        if(file_exists($reqF)) {
            foreach(file($reqF) as $l) {
                if(strpos($l, '<?php') !== false) continue;
                $d = explode('|', trim($l));
                if(($d[0]??'') == $myU && ($d[1]??'') == $cid) { $already = true; break; }
            }
        }
        if(!$already) {
            db_append($reqF, "$myU|$cid|$myN");
        }
    }
    header("Location: ?view=profile&uid=" . $cid); exit;
}

// ОБРАБОТКА ЗАЯВОК: ПРИНЯТЬ ИЛИ ОТКЛОНИТЬ
if(isset($_GET['req_action']) && $myU) {
    $from_uid = preg_replace('/[^a-z0-9]/', '', $_GET['from_uid']);
    $action = $_GET['req_action'];
    if(file_exists($reqF)) {
        $lines = file($reqF); $newLines = ["<?php die(); ?>\n"];
        $sender_name = $from_uid;
        foreach($lines as $l) {
            if(strpos($l, '<?php') !== false || !trim($l)) continue;
            $d = explode('|', trim($l));
            if(($d[0]??'') == $from_uid && ($d[1]??'') == $myU) {
                if(isset($d[2])) $sender_name = trim($d[2]);
                continue; 
            }
            $newLines[] = rtrim(trim($l), "\r\n") . "\n";
        }
        file_put_contents($reqF, implode("", $newLines), LOCK_EX);
        
        if($action == 'accept') {
            db_append($rDir . "contacts_" . $myU . ".db.php", "$from_uid|$sender_name");
            db_append($rDir . "contacts_" . $from_uid . ".db.php", "$myU|$myN");
        }
    }
    header("Location: ?view=digest"); exit;
}

// СМЕНА АВАТАРА И ОПИСАНИЯ ПРОФИЛЯ
if(isset($_POST['up_profile']) && $myU){
    if(!empty($_FILES['ava_file']['tmp_name'])) {
        $check = @getimagesize($_FILES['ava_file']['tmp_name']);
        $ext = strtolower(pathinfo($_FILES['ava_file']['name'], PATHINFO_EXTENSION));
        if($check !== false && in_array($ext, ['png', 'jpg', 'jpeg', 'gif'])) {
            move_uploaded_file($_FILES['ava_file']['tmp_name'], $avatarDir . md5($myU) . '.png');
        }
    }
    if(isset($_POST['about'])) {
        $about_safe = str_replace(["\r", "\n", "|"], " ", htmlspecialchars($_POST['about']));
        file_put_contents($avatarDir . md5($myU) . '.txt', $about_safe);
    }
    header("Location: ?view=profile"); exit;
}

// СОЗДАНИЕ ГРУППЫ / КАНАЛА
if (isset($_POST['create_room']) && $myU) {
    $name = str_replace('|', '-', htmlspecialchars($_POST['r_name']));
    $type = ($_POST['r_type'] == 'channel') ? 'channel' : 'group'; 
    $id = bin2hex(openssl_random_pseudo_bytes(4));
    db_append($groupsF, "$id|$name|$type|$myU");
    header("Location: ?view=groups"); exit;
}

// АВТОРИЗАЦИЯ И РЕГИСТРАЦИЯ
if(isset($_POST['login'])){
    $u = strtolower(preg_replace('/[^a-z0-9]/', '', $_POST['u_id']));
    $p = $_POST['pwd'] ?? ''; 
    $n = str_replace(['|', '?', '<', '>'], '', htmlspecialchars($_POST['dn'] ?? $u));
    if($u && $p){
        $exists = false; $auth = false;
        if(file_exists($passF)) {
            foreach(file($passF) as $l) {
                if(strpos($l, '<?php') !== false) continue;
                $d = explode('|', trim($l));
                if(($d[0] ?? '') == $u) { 
                    $exists = true; 
                    if(password_verify($p, $d[1])) { $auth = true; $n = $d[2] ?? $u; }
                    break; 
                }
            }
        }
        if($auth || !$exists) {
            if(!$exists) db_append($passF, "$u|".password_hash($p, PASSWORD_DEFAULT)."|$n");
            $_SESSION['ce_uid'] = $u; $_SESSION['ce_nick'] = $n;
            header("Location: index.php"); exit;
        } else {
            $_SESSION['ce_error'] = "Неверный пароль!";
        }
    }
}

if(isset($_GET['logout'])){ session_destroy(); header("Location: index.php"); exit; }

// ОТПРАВКА СООБЩЕНИЙ
if($myU && isset($_POST['send_msg'])){
    $m = $_POST['msg'] ?? ''; $fT = ""; $isValidFile = true;
    if(!empty($_FILES['f']['name'])){
        $ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));
        $allowedExtensions = ['jpg','png','gif','jpeg','zip','rar','txt','amr','mp3'];
        $isImageExt = in_array($ext, ['jpg','png','gif','jpeg']);
        if(!in_array($ext, $allowedExtensions)) $isValidFile = false;
        if($isImageExt && $isValidFile) {
            if(@getimagesize($_FILES['f']['tmp_name']) === false) $isValidFile = false;
        }
        if($isValidFile) {
            $nf = bin2hex(openssl_random_pseudo_bytes(8)).'.'.$ext;
            if(move_uploaded_file($_FILES['f']['tmp_name'], $up.$nf)) {
                $fT = $isImageExt ? "[img]".$up.$nf."[/img]" : "[file]".$up.$nf."[/file]";
            }
        }
    }
    if(($m || $fT) && $isValidFile) {
        $safeMyN = str_replace(['|', "\n", "\r"], '', $myN);
        db_append($curF, "$safeMyN|".v_crypt($m.($m&&$fT?" ":"").$fT, $crypto_key)."|".date('H:i')."|$myU|0");
    }
    header("Location: ?view=$view&to=$to"); exit;
}
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CrossEra Messenger</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        html, body { height:100%; width:100%; }
        
        body.theme-light { background:#fdf6e3; color:#657b83; }
        body.theme-light .box { background:#eee8d5; color:#073642; }
        body.theme-light #chat, body.theme-light .main-panel { background:#fdf6e3; color:#586e75; }
        body.theme-light .m { border-bottom:1px solid #eae1c8; }
        body.theme-light .mod-card { background:#eee8d5; border:1px solid #d3cbb7; color:#073642; }
        
        body.theme-dark { background:#073642; color:#93a1a1; }
        body.theme-dark .box { background:#002b36; color:#93a1a1; }
        body.theme-dark #chat, body.theme-dark .main-panel { background:#002b36; color:#839496; }
        body.theme-dark .m { border-bottom:1px solid #073642; }
        body.theme-dark .mod-card { background:#073642; border:1px solid #586e75; color:#93a1a1; }
        body.theme-dark textarea, body.theme-dark input[type="text"] { background:#073642; color:#eee; border:1px solid #586e75; }
        
        body { font-family:sans-serif; font-size:12px; }
        
        /* Классическое блочное позиционирование для стабильного скролла на ретро-ОС */
        .box { width:100%; min-height:100%; display:block; position:relative; }
        .hdr { background:#a01ae8; color:white; padding:10px; font-weight:bold; }
        .nav { background:#93a1a1; padding:5px; border-bottom:1px solid #586e75; }
        body.theme-dark .nav { background:#073642; border-bottom:1px solid #586e75; }
        .nav a { background:#eee; color:#000; text-decoration:none; padding:4px 8px; font-size:10px; border:1px solid #666; border-radius:3px; display:inline-block; margin:2px 1px; }
        .nav a.active { background:#2aa198; color:white; }
        
        .content { width:100%; display:block; padding-bottom:120px; } 
        #chat, .main-panel { padding:10px; display:block; }
        
        .m { padding:8px 0; position:relative; }
        .btn { background:#2aa198; color:white; border:none; padding:4px 10px; cursor:pointer; text-decoration:none; font-size:11px; border-radius:3px; display:inline-block; }
        .mod-card { padding:10px; margin-bottom:8px; border-radius:5px; position:relative; }
        .reac-bar { margin-left:29px; margin-top:4px; display:block; }
        .reac-btn { background:#f0f0f0; border:1px solid #ccc; border-radius:10px; padding:1px 4px; font-size:9px; text-decoration:none; color:#333; display:inline-block; margin-right:3px; }
        body.theme-dark .reac-btn { background:#2a2a2a; border:1px solid #444; color:#ccc; }
        .reac-menu { display:none; position:absolute; background:white; border:1px solid #333; padding:5px; z-index:10; border-radius:5px; bottom:20px; }
        body.theme-dark .reac-menu { background:#222; border-color:#555; }
        .err-msg { background:#dc322f; color:white; padding:8px; margin-bottom:10px; text-align:center; font-weight:bold; }
        .fast-reply { background:#eee; border:1px solid #ccc; padding:2px 5px; font-size:10px; text-decoration:none; color:#000; border-radius:3px; display:inline-block; }
        body.theme-dark .fast-reply { background:#333; border-color:#555; color:#fff; }
        
        /* Фиксированная форма отправки снизу экрана */
        .chat-form-fixed { position:fixed; bottom:0; left:0; width:100%; background:#eee; border-top:1px solid #ccc; padding:6px; z-index:100; }
        body.theme-dark .chat-form-fixed { background:#002b36; border-top:1px solid #586e75; }
    </style>
</head>
<body class="theme-<?php echo $theme; ?>">
<div class="box">
    <?php if(!$myU): ?>
        <div class="hdr"><span>Вход и регистрация в CrossEra</span></div>
        <div class="main-panel">
            <?php if(isset($_SESSION['ce_error'])): echo "<div class='err-msg'>".$_SESSION['ce_error']."</div>"; unset($_SESSION['ce_error']); endif; ?>
            <form method="POST" style="max-width:300px; margin:20px auto;">
                ID (логин латиницей): <input name="u_id" required style="width:100%; padding:5px; margin-bottom:5px;"><br>
                Ник (отображаемое имя): <input name="dn" style="width:100%; padding:5px; margin-bottom:5px;"><br>
                Пароль: <input name="pwd" type="password" required style="width:100%; padding:5px; margin-bottom:10px;"><br>
                <input type="submit" name="login" value="Войти / Создать" class="btn" style="width:100%;">
            </form>
        </div>
    <?php else: ?>
        <div class="hdr">
            <a href="?view=profile&uid=<?php echo $myU; ?>" style="color:white; text-decoration:none;">
                <?php echo get_avatar_html($myU, $myN); ?> <span><?php echo $myN; ?></span>
            </a>
            <div style="float:right;">
                <a href="?view=search" style="color:white; margin-right:10px; text-decoration:none;">Поиск</a>
                <a href="?logout=1" style="color:white; font-size:10px;">[Выход]</a>
            </div>
            <div style="clear:both;"></div>
        </div>

        <div class="nav">
            <a href="?view=chat&to=all" class="<?php echo ($view=='chat'&&$to=='all')?'active':''; ?>">Общий Чат</a>
            <a href="?view=groups" class="<?php echo ($view=='groups'||strpos($to,'group_')===0||strpos($to,'gb_')===0)?'active':''; ?>">Группы/Каналы</a>
            <a href="?view=contacts" class="<?php echo ($view=='contacts')?'active':''; ?>">Контакты</a>
            <a href="?view=chat&to=saved" class="<?php echo ($view=='chat'&&$to=='saved_'.$myU)?'active':''; ?>">Избранное</a>
            <a href="?view=mods_page" class="<?php echo ($view=='mods_page'||$view=='edit_mod'||$view=='run_mod'||$view=='dev_info')?'active':''; ?>">Модули</a>
            <a href="?view=digest" class="<?php echo ($view=='digest')?'active':''; ?>">Дайджест</a>
            <a href="?view=profile&uid=<?php echo $myU; ?>" class="<?php echo ($view=='profile'&&($_GET['uid']??'')==$myU)?'active':''; ?>">Инфо</a>
            <a href="?view=eula" class="<?php echo ($view=='eula')?'active':''; ?>">EULA</a>
            <a href="?view=license" class="<?php echo ($view=='license')?'active':''; ?>">Лицензия</a>
        </div>

        <div class="content">
            <?php if($view == 'digest'): ?>
                <div class="main-panel">
                    <h3>Текстовый дайджест обновлений</h3><br>
                    
                    <?php 
                    if(file_exists($reqF)):
                        foreach(file($reqF) as $l):
                            if(strpos($l, '<?php') !== false || !trim($l)) continue;
                            $d = explode('|', trim($l));
                            if(($d[1]??'') == $myU):
                                $from_id = htmlspecialchars($d[0]);
                                $from_name = htmlspecialchars($d[2] ?? $d[0]);
                    ?>
                                <div class="mod-card" style="background:#b58900; color:white; border:none;">
                                    Пользователь <b><?php echo $from_name; ?></b> (@<?php echo $from_id; ?>) хочет добавить вас в контакты.
                                    <div style="margin-top:5px;">
                                        <a href="?req_action=accept&from_uid=<?php echo $from_id; ?>" class="btn" style="background:#2aa198;">Принять</a>
                                        <a href="?req_action=reject&from_uid=<?php echo $from_id; ?>" class="btn" style="background:#dc322f;">Отклонить</a>
                                    </div>
                                </div>
                    <?php 
                            endif;
                        endforeach;
                    endif; 
                    ?>

                    <div class="mod-card">
                        <b>Общий чат:</b> <?php echo has_new_messages($myU, 'all', $rDir.'global.db.php') ? "<span style='color:red;'>Есть новые сообщения!</span>" : "Нет обновлений"; ?>
                    </div>
                    <h4>Ваши группы и каналы:</h4><br>
                    <?php 
                    if(file_exists($groupsF)) {
                        foreach(file($groupsF) as $l) {
                            if(strpos($l, '<?php') !== false || !trim($l)) continue;
                            $g = explode('|', trim($l));
                            $g_target = "group_" . preg_replace('/[^a-z0-9_]/', '', $g[0]);
                            echo "<div class='mod-card'><b>" . htmlspecialchars($g[1]) . ":</b> " . (has_new_messages($myU, $g_target, $rDir.$g_target.".db.php") ? "<span style='color:red;'>Новые посты!</span>" : "Тишина") . "</div>";
                        }
                    }
                    ?>
                </div>

            <?php elseif($view == 'mods_page'): ?>
                <div class="main-panel">
                    <div style="margin-bottom:10px;">
                        <h3 style="display:inline-block;">Репозиторий модулей</h3>
                        <a href="?view=dev_info" class="btn" style="background:#586e75; font-size:10px; float:right;">Для разработчиков</a>
                        <div style="clear:both;"></div>
                    </div>
                    <p style="font-size:10px; opacity:0.7; margin-bottom:10px;">Автономные расширения системы из каталога.</p>
                    <?php 
                    $modFiles = glob($modDir . "*.php");
                    if(!empty($modFiles)):
                        foreach($modFiles as $mf):
                            $modName = basename($mf, ".php");
                    ?>
                            <div class="mod-card">
                                <b>Модуль: <?php echo htmlspecialchars($modName); ?></b><br>
                                <small style="opacity:0.6;">Путь: <?php echo htmlspecialchars($mf); ?></small>
                                <div style="margin-top:8px;">
                                    <a href="?view=run_mod&name=<?php echo urlencode($modName); ?>" class="btn">Запустить</a>
                                    <a href="?view=edit_mod&name=<?php echo urlencode($modName); ?>" class="btn" style="background:#b58900;">Исходный код</a>
                                </div>
                            </div>
                    <?php 
                        endforeach;
                    else: 
                        echo "<div class='mod-card' style='text-align:center; padding:20px; color:#777;'>";
                        echo "Папка <b>/mods/</b> пуста.<br>Отправьте готовый модуль на mindindevin@gmail.com";
                        echo "</div>";
                    endif; 
                    ?>
                </div>

            <?php elseif($view == 'dev_info'): ?>
                <div class="main-panel">
                    <h3>Документация разработчика модулей</h3><br>
                    <div class="mod-card" style="background:rgba(0,0,0,0.03); font-size:11px; line-height:1.5;">
                        <p>Для публикации вашего плагина в репозитории отправьте готовый скрипт на почту: <b>mindindevin@gmail.com</b></p>
                    </div>
                    <br>
                    <textarea style="width:100%; height:320px; font-family:monospace; font-size:10px; padding:8px; line-height:1.4;" readonly>Разработка расширений для платформы CrossEra Engine.

1. Архитектура интеграции
Все модули должны размещаться в директории /mods/
Ядро index.php подключает модуль, если передан параметр ?view=run_mod&name=имя_файла.
Исполнение происходит внутри контекста основного движка, поэтому внутри файла модуля доступны:
- Настройки и конфигурация (например, ключ $crypto_key).
- Сессии авторизованного пользователя ($_SESSION['ce_uid'], $_SESSION['ce_nick']).
- Системные функции для работы с файлами баз данных (например, db_append()).

2. Основные правила разработки (Стандарт CrossEra)

Правило 1: Отсутствие глобальных HTML-тегов
Так как ядро самостоятельно рендерит doctype, теги html, head и body, внутри файла модуля запрещено дублировать эти элементы. Модуль должен содержать только изолированную разметку (div, form, table).

Правило 2: Правильная адресация форм и ссылок
При использовании POST-форм или ссылок необходимо сохранять GET-параметры ядра, иначе контекст модуля потеряется.
Пример динамического формирования URL:
$currentModName = preg_replace('/[^a-z0-9_\-]/i', '', $_GET['name'] ?? 'my_mod');
$modUrl = "?view=run_mod&name=" . urlencode($currentModName);
Переменную $modUrl необходимо использовать во всех атрибутах action и href.

Правило 3: Безопасный Post-Redirect-Get (PRG)
Для предотвращения повторной отправки данных при обновлении страницы в прокси-браузерах (Opera Mini) после обработки любого $_POST запроса обязательно выполняйте редирект на адрес модуля и завершайте скрипт:
if (isset($_POST['my_action'])) {
    // Обработка данных
    header("Location: " . $modUrl);
    exit;
}

Правило 4: Изоляция CSS-стилей
Оборачивайте всю верстку модуля в уникальный CSS-контейнер, чтобы стили не нарушали отображение основного интерфейса мессенджера.
Неправильно: .btn { color: red; } (перезапишет стиль кнопок чата).
Правильно: .my-mod-container .mod-btn { color: red; }

3. Ограничения для старых платформ
- Сессии: Мобильные прокси-браузеры могут кэшировать сессии по IP. Проверяйте статус сессии через session_status().
- JavaScript: Интерфейсы CrossEra должны сохранять полную работоспособность при отключенном JavaScript. Логика модулей обязана обрабатываться на стороне PHP. Использование JS допускается только для декоративных улучшений на современных устройствах.
- Объем данных: Оптимальный объем генерируемой модулем страницы — в пределах 60-100 Кб.</textarea>
                    <br><br>
                    <a href="?view=mods_page" class="btn" style="background:#586e75;">Назад к репозиторию</a>
                </div>

            <?php elseif($view == 'eula'): ?>
                <div class="main-panel">
                    <h3>Лицензионное соглашение (EULA)</h3><br>
                    <div class="mod-card" style="line-height:1.6; font-size:11px; text-align:justify;">
                        <b>1. Общие положения</b><br>
                        Используя мессенджер CrossEra, вы соглашаетесь с условиями настоящего лицензионного соглашения. Если вы не согласны с условиями, прекратите использование платформы.<br><br>
                        
                        <b>2. Правила использования и контент</b><br>
                        Пользователь несет полную ответственность за передаваемую информацию, текстовые сообщения и медиафайлы. Запрещено использование платформы для распространения вредоносного ПО, спама, оскорблений, нарушений законодательства, а также любого контента, нарушающего права третьих лиц.<br><br>
                        
                        <b>3. Отказ от гарантий (As Is)</b><br>
                        Программное обеспечение предоставляется по принципу "как есть" (As Is). Разработчик не несет ответственности за любые сбои в работе движка, потерю данных, сессий или кэша прокси-браузеров, а также за временную недоступность сервиса на оконечных устройствах пользователя.<br><br>
                        
                        <b>4. Конфиденциальность и безопасность</b><br>
                        Платформа использует встроенные механизмы криптографического шифрования для защиты сообщений (AES-128-CTR). Тем не менее, пользователь самостоятельно отвечает за надежность своего пароля. Администрация не имеет доступа к утерянным паролям ввиду их необратимого хеширования (password_hash).<br><br>
                        
                        <small style="opacity:0.6;">Редакция соглашения от: <?php echo date('Y-m-d'); ?>. Платформа CrossEra Engine.</small>
                    </div>
                </div>

            <?php elseif($view == 'license'): ?>
                <div class="main-panel">
                    <h3>Лицензия исходного кода (MIT License)</h3><br>
                    <textarea style="width:100%; height:280px; font-family:monospace; font-size:10px; padding:8px; line-height:1.4;" readonly>Copyright (c) <?php echo date('Y'); ?> CrossEra Engine

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.</textarea>
                    <br><br>
                    <div class="mod-card" style="font-size:11px;">
                        <b>Примечание:</b> Данная лицензия распространяется на исходный код движка мессенджера и позволяет свободно модифицировать, копировать и создавать форки проекта.
                    </div>
                </div>

            <?php elseif($view == 'run_mod'): ?>
                <div class="main-panel">
                    <?php 
                    $mName = preg_replace('/[^a-z0-9_\-]/i', '', $_GET['name'] ?? '');
                    $mPath = $modDir . $mName . ".php";
                    if(file_exists($mPath)) {
                        include($mPath);
                    } else {
                        echo "<div class='err-msg'>Модуль не найден!</div>";
                    }
                    ?>
                </div>

            <?php elseif($view == 'edit_mod'): ?>
                <div class="main-panel">
                    <?php 
                    $mName = preg_replace('/[^a-z0-9_\-]/i', '', $_GET['name'] ?? '');
                    $mPath = $modDir . $mName . ".php";
                    if(file_exists($mPath)): ?>
                        <h3>Код модуля: <?php echo htmlspecialchars($mName); ?>.php</h3><br>
                        <textarea style="width:100%; height:280px; font-family:monospace; font-size:11px; padding:5px;" readonly><?php echo htmlspecialchars(file_get_contents($mPath)); ?></textarea><br><br>
                        <a href="?view=mods_page" class="btn" style="background:#586e75;">Назад к списку</a>
                    <?php else: echo "Модуль не найден."; endif; ?>
                </div>

            <?php elseif($view == 'search'): ?>
                <div class="main-panel">
                    <h3>Поиск по всей платформе</h3><br>
                    <form method="GET" style="margin-bottom:15px;">
                        <input type="hidden" name="view" value="search">
                        <input type="text" name="q" value="<?php echo htmlspecialchars($_GET['q']??''); ?>" placeholder="Что искать?" style="padding:5px; width:70%;">
                        <input type="submit" value="Найти" class="btn">
                    </form>
                    <?php 
                    $q = strtolower(htmlspecialchars($_GET['q']??''));
                    if($q):
                        echo "<h4>Результаты поиска:</h4><br>";
                        echo "<b>Люди:</b><br>";
                        if(file_exists($passF)) {
                            foreach(file($passF) as $l) {
                                if(strpos($l, '<?php')!==false) continue;
                                $d = explode('|', trim($l));
                                if(strpos(strtolower($d[0]??''), $q)!==false || strpos(strtolower($d[2]??''), $q)!==false) {
                                    echo "• <a href='?view=profile&uid={$d[0]}'>".htmlspecialchars($d[2])." (@{$d[0]})</a><br>";
                                }
                            }
                        }
                        echo "<br><b>Группы и Каналы:</b><br>";
                        if(file_exists($groupsF)) {
                            foreach(file($groupsF) as $l) {
                                if(strpos($l, '<?php')!==false) continue;
                                $d = explode('|', trim($l));
                                if(strpos(strtolower($d[1]??''), $q)!==false) {
                                    $target = "group_".preg_replace('/[^a-z0-9_]/','',$d[0]);
                                    echo "• <a href='?view=chat&to={$target}'>".htmlspecialchars($d[1])." (".($d[2]=='channel'?'Канал':'Группа').")</a><br>";
                                }
                            }
                        }
                        echo "<br><b>Сообщения из общего чата:</b><br>";
                        if(file_exists($rDir."global.db.php")) {
                            foreach(file($rDir."global.db.php") as $l) {
                                if(strpos($l, '<?php') !== false) continue;
                                $d = explode('|', trim($l));
                                $msg = v_crypt($d[1]??'', $crypto_key, 'dec');
                                if(strpos(strtolower($msg), $q)!==false) {
                                    echo "<div class='mod-card' style='font-size:11px;'><b>{$d[0]}:</b> ".parse_msg($msg)."</div>";
                                }
                            }
                        }
                    endif;
                    ?>
                </div>

            <?php elseif($view == 'profile'): ?>
                <?php 
                $uid = preg_replace('/[^a-z0-9_]/', '', $_GET['uid'] ?? $myU);
                $cf = $viewsDir . md5($uid) . '.txt';
                $views = file_exists($cf) ? (int)file_get_contents($cf) : 0;
                if($uid != $myU) { $views++; file_put_contents($cf, $views); }
                
                $name = $uid; $about = "О себе ничего не указано.";
                if(file_exists($passF)) {
                    foreach(file($passF) as $l) {
                        $d = explode('|', trim($l));
                        if(($d[0]??'') == $uid) { $name = $d[2]??$uid; break; }
                    }
                }
                if(file_exists($avatarDir . md5($uid) . '.txt')) $about = file_get_contents($avatarDir . md5($uid) . '.txt');
                ?>
                <div class="main-panel" style="text-align:center;">
                    <?php echo get_avatar_html($uid, $name); ?><br><br>
                    <h3><?php echo htmlspecialchars($name); ?> (@<?php echo $uid; ?>)</h3>
                    <p style="font-size:10px; color:#777; margin-top:4px;">Просмотров профиля: <b><?php echo $views; ?></b></p>
                    <hr style="margin:15px 0; opacity:0.2;">
                    <div class="mod-card" style="text-align:left; min-height:60px;">
                        <b>Инфо (.plan файл):</b><br><?php echo nl2br(htmlspecialchars($about)); ?>
                    </div>
                    
                    <?php if($uid == $myU): ?>
                        <form method="POST" enctype="multipart/form-data" style="text-align:left;" class="mod-card">
                            <b>Редактировать визитку:</b><br><br>
                            <label style="font-size:10px;">Аватар:</label> <input type="file" name="ava_file"><br><br>
                            <label style="font-size:10px;">О себе:</label><br>
                            <textarea name="about" style="width:100%; height:50px;"><?php echo htmlspecialchars($about); ?></textarea><br><br>
                            <input type="submit" name="up_profile" value="Сохранить визитку" class="btn">
                            <a href="?toggle_theme=1" class="btn" style="background:#586e75; float:right;">Сменить тему</a>
                        </form>
                    <?php else: ?>
                        <a href="?add_c=<?php echo $uid; ?>" class="btn">+ Добавить в контакты</a>
                        <a href="?view=chat&to=<?php echo ($myU < $uid) ? "pm_{$myU}_{$uid}" : "pm_{$uid}_{$myU}"; ?>" class="btn" style="background:#a01ae8;">Написать ЛС</a>
                    <?php endif; ?>
                </div>

            <?php elseif($view == 'edit'): ?>
                <div class="main-panel">
                    <h3>Редактирование сообщения</h3><br>
                    <?php 
                    $mid = preg_replace('/[^a-z0-9]/', '', $_GET['mid'] ?? '');
                    $old_text = '';
                    if(file_exists($curF)) {
                        foreach(file($curF) as $l) {
                            if(md5(trim($l)) == $mid) {
                                $d = explode('|', trim($l));
                                if(($d[3]??'') == $myU) $old_text = v_crypt($d[1], $crypto_key, 'dec');
                                break;
                            }
                        }
                    }
                    if($old_text): ?>
                        <form method="POST">
                            <input type="hidden" name="mid" value="<?php echo $mid; ?>">
                            <textarea name="new_text" style="width:100%; height:60px; padding:5px;"><?php echo htmlspecialchars($old_text); ?></textarea><br><br>
                            <input type="submit" name="edit_msg" value="Применить изменения" class="btn">
                            <a href="?view=chat&to=<?php echo $to; ?>" class="btn" style="background:#586e75;">Отмена</a>
                        </form>
                    <?php else: echo "Сообщение не найдено или доступ запрещен."; endif; ?>
                </div>

            <?php elseif($view == 'groups'): ?>
                <div class="main-panel">
                    <h3>Каналы и Группы</h3><br>
                    <form method="POST" style="background:rgba(0,0,0,0.05); padding:10px; border-radius:5px; margin-bottom:15px;">
                        <input name="r_name" required placeholder="Название комнаты" style="padding:4px;">
                        <select name="r_type" style="padding:3px;"><option value="group">Группа (Чат)</option><option value="channel">Канал (Стена)</option></select>
                        <input type="submit" name="create_room" value="Создать" class="btn">
                    </form>
                    <?php if(file_exists($groupsF)) foreach(file($groupsF) as $l): if(strpos($l,'<?php')!==false || !trim($l))continue; $g=explode('|',trim($l)); 
                        $g0_safe = preg_replace('/[^a-z0-9_]/', '', $g[0]);
                        $g_target = "group_" . $g0_safe;
                        ?>
                        <div class="mod-card">
                            <b>[<?php echo ($g[2]=='channel'?'Канал':'Группа'); ?>] <?php echo htmlspecialchars($g[1]); ?></b> 
                            <a href="?view=chat&to=<?php echo $g_target; ?>" class="btn" style="float:right;">Войти</a>
                        </div>
                    <?php endforeach; ?>
                </div>

            <?php elseif($view == 'contacts'): ?>
                <div class="main-panel">
                    <h3>Мои контакты</h3><br>
                    <?php $cf = $rDir . "contacts_" . $myU . ".db.php"; if(file_exists($cf)): 
                        foreach(file($cf) as $l): if(strpos($l,'<?php')!==false || !trim($l))continue; $c=explode('|',trim($l)); 
                        $c0_safe = preg_replace('/[^a-z0-9_]/', '', $c[0]);
                        $pm = ($myU < $c0_safe) ? "pm_{$myU}_{$c0_safe}" : "pm_{$c0_safe}_{$myU}"; 
                        ?>
                        <div class="mod-card">
                            <?php echo get_avatar_html($c0_safe, $c[1]); ?> 
                            <b><?php echo htmlspecialchars($c[1]); ?></b> 
                            <a href="?view=chat&to=<?php echo $pm; ?>" class="btn" style="float:right;">Диалог</a>
                        </div>
                    <?php endforeach; else: echo "Список пуст"; endif; ?>
                </div>

            <?php elseif($view == 'chat'): ?>
                <?php 
                $isChannel = false; $channelOwner = '';
                if(strpos($to, 'group_') === 0) {
                    $r_id = str_replace('group_', '', $to);
                    if(file_exists($groupsF)) {
                        foreach(file($groupsF) as $gl) {
                            $gd = explode('|', trim($gl));
                            if($gd[0] == $r_id && ($gd[2]??'') == 'channel') { $isChannel = true; $channelOwner = $gd[3]??''; break; }
                        }
                    }
                }
                $isGuestbook = (strpos($to, 'gb_') === 0);
                ?>
                <div style="background:rgba(0,0,0,0.02); padding:5px 10px; font-size:10px; margin-bottom: 5px;">
                    <span>Комната: <b><?php echo $to; ?></b> <?php if($isChannel) echo "(Публичный Канал)"; if($isGuestbook) echo "(Гостевая книга)"; ?></span>
                    <a href="?export_txt=1&to=<?php echo $to; ?>" style="color:#2aa198; text-decoration:none; float:right;">Скачать (.TXT)</a>
                    <div style="clear:both;"></div>
                </div>

                <div id="chat">
                    <?php 
                    if(file_exists($curF)):
                        $lines = file($curF);
                        foreach($lines as $idx => $l):
                            if(strpos($l, '<?php') !== false || !trim($l)) continue;
                            $d = explode('|', trim($l)); if(count($d) < 3) continue; 
                            $uid = preg_replace('/[^a-z0-9_]/', '', $d[3] ?? ''); 
                            $msgID = md5(trim($l));
                            $plainMsg = v_crypt($d[1], $crypto_key, 'dec');
                            $isEdited = ($d[4] ?? 0) == 1;
                    ?>
                            <div class="m">
                                <?php echo get_avatar_html($uid, $d[0]); ?>
                                <a href="?view=profile&uid=<?php echo $uid; ?>" style="text-decoration:none; color:inherit;"><b><?php echo $d[0]; ?></b></a>
                                
                                <span style="float:right; opacity:0.5; font-size:10px;">
                                    <?php echo htmlspecialchars($d[2]); ?> <?php if($isEdited) echo "<i>(ред.)</i>"; ?>
                                    <?php if($uid == $myU && $plainMsg !== "[Сообщение удалено]"): ?>
                                        <a href="?view=edit&mid=<?php echo $msgID; ?>&to=<?php echo $to; ?>" style="color:#b58900; text-decoration:none; margin-left:5px;">[ред]</a>
                                    <?php endif; ?>
                                    <?php if(($uid == $myU || $myU == $adminID) && $plainMsg !== "[Сообщение удалено]"): ?>
                                        <a href="?del_msg=<?php echo $msgID; ?>&to=<?php echo $to; ?>" style="color:#dc322f; text-decoration:none; margin-left:5px;">[x]</a>
                                    <?php endif; ?>
                                </span><br>
                                
                                <div style="margin-left:29px; margin-top:3px; font-size:13px;"><?php echo parse_msg($plainMsg); ?></div>
                                
                                <?php if($isChannel && !$isGuestbook): ?>
                                    <div style="margin-left:29px; margin-top:4px;">
                                        <a href="?view=chat&to=gb_<?php echo $msgID; ?>" style="font-size:10px; color:#2aa198; text-decoration:none;">Гостевая книга (Отзывы)</a>
                                    </div>
                                <?php endif; ?>

                                <div class="reac-bar">
                                    <?php 
                                    $rf = $reacDir . $msgID . ".db.php";
                                    if(file_exists($rf)) {
                                        $rcs = file($rf); $counts = [];
                                        foreach($rcs as $rl) {
                                            if(strpos($rl, '<?php') !== false) continue;
                                            $d_r = explode('|', trim($rl));
                                            if(isset($d_r[2])) {
                                                $safe_reac = preg_replace('/[^a-z0-9\.]/', '', $d_r[2]);
                                                $counts[$safe_reac] = ($counts[$safe_reac] ?? 0) + 1;
                                            }
                                        }
                                        foreach($counts as $img => $count) {
                                            echo "<span class='reac-btn'><img src='smiles/" . htmlspecialchars($img) . "' width='12'> " . (int)$count . "</span>";
                                        }
                                    }
                                    ?>
                                    <a href="#" onclick="document.getElementById('rm<?php echo $idx;?>').style.display='block'; return false;" class="reac-btn">+</a>
                                    <div id="rm<?php echo $idx;?>" class="reac-menu">
                                        <?php foreach(['fire.gif','smile.gif','good.gif','heart.gif'] as $t) echo "<a href='?add_reac=1&mid=$msgID&type=$t&to=$to'><img src='smiles/$t' width='16'></a> "; ?>
                                        <a href="#" onclick="this.parentElement.style.display='none'; return false;" style="color:red; text-decoration:none;">[x]</a>
                                    </div>
                                </div>
                            </div>
                    <?php 
                        endforeach;
                    endif; 
                    ?>
                </div>

                <?php if(!$isChannel || $channelOwner == $myU || $isGuestbook): ?>
                    <form method="POST" enctype="multipart/form-data" class="chat-form-fixed">
                        <div style="margin-bottom:5px;">
                            <span style="font-size:9px; opacity:0.6;">Быстро:</span>
                            <a href="#" class="fast-reply" onclick="document.getElementsByName('msg')[0].value+='Да'; return false;">Да</a>
                            <a href="#" class="fast-reply" onclick="document.getElementsByName('msg')[0].value+='Нет'; return false;">Нет</a>
                            <a href="#" class="fast-reply" onclick="document.getElementsByName('msg')[0].value+='Ок'; return false;">Ок</a>
                        </div>
                        <textarea name="msg" style="width:100%; height:35px; border-radius:3px; padding:4px;" placeholder="Ваше сообщение..."></textarea>
                        <div style="margin-top:4px;">
                            <input type="file" name="f" style="font-size:10px; width:60%;">
                            <input type="submit" name="send_msg" value="&gt;&gt;" class="btn" style="padding:3px 12px; float:right;">
                        </div>
                    </form>
                <?php else: ?>
                    <div class="chat-form-fixed" style="text-align:center; font-size:11px; color:#666; padding:10px;">Это канал. Писать сюда может только создатель.</div>
                <?php endif; ?>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>
</body>
</html>
