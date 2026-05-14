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

$myU = $_SESSION['ce_uid'] ?? $_COOKIE['ce_uid'] ?? '';
$myN = $_SESSION['ce_nick'] ?? $_COOKIE['ce_nick'] ?? '';

$groupsF = $rDir . 'groups_list.db.php';
$myContactsF = $rDir . "contacts_" . $myU . ".db.php";
$userModsFile = $rDir . "mods_user_" . $myU . ".db.php";

function db_append($f, $d) {
    if(!file_exists($f)) file_put_contents($f, "<?php die(); ?>\n");
    return file_put_contents($f, $d . "\n", FILE_APPEND | LOCK_EX);
}

function v_crypt($d, $k, $mode = 'enc') {
    if ($mode == 'enc') {
        $iv = openssl_random_pseudo_bytes(16);
        $enc = openssl_encrypt($d, "aes-128-ctr", $k, 0, $iv);
        return "A:" . str_replace(['+','/','='], ['-','_',''], base64_encode($iv . "::" . $enc));
    } else {
        if (substr($d, 0, 2) !== "A:") return $d;
        $raw = base64_decode(str_replace(['-','_'], ['+','/'], substr($d, 2)));
        $p = explode("::", $raw);
        return openssl_decrypt($p[1] ?? '', "aes-128-ctr", $k, 0, $p[0] ?? '');
    }
}

function get_avatar_html($u, $name) {
    global $avatarDir;
    $f = $avatarDir . md5($u) . '.png';
    if(file_exists($f)) return "<img src='$f?".filemtime($f)."' width='24' height='24' style='vertical-align:middle; border-radius:50%; margin-right:5px;'>";
    $colors = ['#268bd2', '#b58900', '#cb4b16', '#dc322f', '#2aa198'];
    $c = $colors[abs(crc32($u)) % count($colors)];
    $l = mb_strtoupper(mb_substr($name ?? 'U', 0, 1));
    return "<div style='display:inline-block; width:24px; height:24px; border-radius:50%; background:$c; color:white; text-align:center; line-height:24px; font-size:10px; vertical-align:middle; margin-right:5px;'>$l</div>";
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

if(isset($_POST['up_ava']) && $myU){
    if(!empty($_FILES['ava_file']['tmp_name'])) move_uploaded_file($_FILES['ava_file']['tmp_name'], $avatarDir . md5($myU) . '.png');
    header("Location: ?view=profile"); exit;
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
    if(in_array($m, $myEnabledMods)) $myEnabledMods = array_diff($myEnabledMods, [$m]);
    else if(file_exists($modDir . $m . ".php")) $myEnabledMods[] = $m;
    file_put_contents($userModsFile, "<?php die(); ?>\n" . implode("\n", array_unique($myEnabledMods)));
    header("Location: ?view=mod_store"); exit;
}

if(isset($_POST['login'])){
    $u = strtolower(preg_replace('/[^a-z0-9]/', '', $_POST['u_id']));
    $p = $_POST['pwd'] ?? ''; $n = htmlspecialchars($_POST['dn'] ?? $u);
    if($u && $p){
        $passF = $rDir . 'users_pass.db.php'; $exists = false; $auth = false;
        if(file_exists($passF)) {
            foreach(file($passF) as $l) {
                $d = explode('|', trim($l));
                if(($d[0] ?? '') == $u) { $exists = true; if(password_verify($p, $d[1])) $auth = true; break; }
            }
        }
        if($auth || !$exists) {
            if(!$exists) db_append($passF, "$u|".password_hash($p, PASSWORD_DEFAULT));
            $_SESSION['ce_uid'] = $u; $_SESSION['ce_nick'] = $n;
            setcookie('ce_uid', $u, time()+86400*30, "/"); header("Location: index.php"); exit;
        }
    }
}
if(isset($_GET['logout'])){ session_destroy(); header("Location: index.php"); exit; }

$view = $_GET['view'] ?? 'chat';
$to = preg_replace('/[^a-z0-9_]/', '', $_GET['to'] ?? 'all');
$curF = $rDir . (strpos($to, 'pm_') === 0 || strpos($to, 'saved_') === 0 || strpos($to, 'group_') === 0 ? "$to.db.php" : "room_$to.db.php");
if($to == 'all') $curF = $rDir . "global.db.php";

if($myU && isset($_POST['send_msg'])){
    $m = $_POST['msg'] ?? ''; $fT = "";
    if(!empty($_FILES['f']['name'])){
        $ext = strtolower(pathinfo($_FILES['f']['name'], PATHINFO_EXTENSION));
        $nf = bin2hex(openssl_random_pseudo_bytes(5)).'.'.$ext;
        if(move_uploaded_file($_FILES['f']['tmp_name'], $up.$nf))
            $fT = in_array($ext, ['jpg','png','gif','jpeg']) ? "[img]".$up.$nf."[/img]" : "[file]".$up.$nf."[/file]";
    }
    if($m || $fT) db_append($curF, "$myN|".v_crypt($m.($m&&$fT?" ":"").$fT, $crypto_key)."|".date('H:i')."|$myU");
    header("Location: ?view=$view&to=$to"); exit;
}
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
        body { margin:0; font-family:sans-serif; background:#000; color:#839496; font-size:12px; }
        .box { height:100%; width:100%; background:#eee8d5; color:#073642; display:flex; flex-direction:column; overflow:hidden; }
        .hdr { background:#a01ae8; color:white; padding:10px; font-weight:bold; display:flex; justify-content:space-between; align-items:center; flex-shrink:0; }
        .nav { background:#93a1a1; padding:5px; display:flex; flex-wrap:wrap; gap:3px; border-bottom:1px solid #586e75; flex-shrink:0; }
        .nav a { background:#eee; color:#000; text-decoration:none; padding:4px 8px; font-size:10px; border:1px solid #666; border-radius:3px; }
        .nav a.active { background:#2aa198; color:white; }
        .content { flex:1; display:flex; flex-direction:column; overflow:hidden; min-height:0; }
        #chat { flex:1; overflow-y:auto; background:#fff; padding:10px; }
        .m { border-bottom:1px solid #eee; padding:8px 0; position:relative; }
        .btn { background:#2aa198; color:white; border:none; padding:6px 12px; cursor:pointer; text-decoration:none; font-size:11px; border-radius:3px; display:inline-block; }
        .mod-card { background:#fff; border:1px solid #ccc; padding:10px; margin-bottom:8px; border-radius:5px; }
        .reac-bar { margin-left:29px; margin-top:4px; display:flex; gap:3px; align-items:center; }
        .reac-btn { background:#f0f0f0; border:1px solid #ccc; border-radius:10px; padding:1px 4px; font-size:9px; text-decoration:none; color:#333; }
        .reac-menu { display:none; position:absolute; background:white; border:1px solid #333; padding:5px; z-index:10; border-radius:5px; bottom:20px; }
    </style>
</head>
<body>
<div class="box">
    <?php if(!$myU): ?>
        <div style="height:100%; display:flex; align-items:center; justify-content:center; background:#000;">
            <div style="background:#111; padding:40px; border-radius:10px; text-align:center; width:90%; max-width:350px;">
                <?php if(file_exists('logo.jpg')): ?>
                    <img src="logo.jpg" style="width:80%; max-width:200px; margin-bottom:20px;">
                <?php else: ?>
                    <h2 style="color:#a01ae8;">CrossEra</h2>
                <?php endif; ?>
                <form method="POST">
                    <input name="u_id" placeholder="ID" style="width:100%; padding:8px; margin:5px 0; background:#222; color:#fff; border:1px solid #333; border-radius:3px;"><br>
                    <input name="dn" placeholder="Ник" style="width:100%; padding:8px; margin:5px 0; background:#222; color:#fff; border:1px solid #333; border-radius:3px;"><br>
                    <input name="pwd" type="password" placeholder="Пароль" style="width:100%; padding:8px; margin:5px 0; background:#222; color:#fff; border:1px solid #333; border-radius:3px;"><br>
                    <input type="submit" name="login" value="ВХОД" class="btn" style="width:100%; margin-top:10px;">
                </form>
                <p style="color:#666; font-size:9px; margin-top:30px;">© Impisre Software</p>
            </div>
        </div>
    <?php else: ?>
        <div class="hdr">
            <a href="?view=profile" style="color:white; text-decoration:none;"><?php echo get_avatar_html($myU, $myN); ?> <?php echo $myN; ?></a>
            <a href="?logout=1" style="color:white; font-size:10px; text-decoration:none;">[Выход]</a>
        </div>

        <div class="nav">
            <a href="?view=chat&to=all" class="<?php echo ($to=='all')?'active':''; ?>">🌍 Чат</a>
            <a href="?view=groups" class="<?php echo ($view=='groups')?'active':''; ?>">📢 Группы</a>
            <a href="?view=contacts" class="<?php echo ($view=='contacts')?'active':''; ?>">📖 Контакты</a>
            <a href="?view=chat&to=saved_<?php echo $myU; ?>" class="<?php echo ($to=='saved_'.$myU)?'active':''; ?>">⭐ Избр.</a>
            <a href="?view=mod_store" class="<?php echo ($view=='mod_store')?'active':''; ?>">📦 Моды</a>
            <a href="?view=info" class="<?php echo ($view=='info')?'active':''; ?>">ℹ️ Инфа</a>
            <?php foreach($myEnabledMods as $m): ?>
                <a href="?view=run_<?php echo $m; ?>" style="background:#b58900; color:#fff;">🧩 <?php echo substr($m,0,4); ?></a>
            <?php endforeach; ?>
        </div>

        <div class="content">
            <?php if($view == 'info'): ?>
                <div style="padding:20px; background:#fff; flex:1; overflow-y:auto; line-height:1.6; color:#333;">
                    <div style="margin-bottom: 20px;">
                        <img src="logo.png" alt="CrossEra Logo" style="width: 80%; max-width: 280px;">
                    </div>
                    <div style="background:#f9f9f9; border-left:4px solid #a01ae8; padding:10px; margin-bottom:15px; font-size:11px;">
                        <strong>Impisre Software</strong> представляет: кросс-платформенный мессенджер.
                    </div>
                    <h3 style="font-size:14px; border-bottom:1px solid #eee;">🛠 Возможности</h3>
                    <ul style="padding-left:20px; font-size:11px;">
                        <li><b>AES-128:</b> облачное шифрование сообщений с помощью openSSL.</li>
                        <li><b>Кросс-потформенный:</b> Работа на многих ОС.</li>
                        <li><b>Модули:</b> Расширение функций с помощью пользовательский модулей которые модерируются.</li>
                        <li><b>Реакции:</b> Быстрый отклик на сообщения.</li>
                        <li><b>нету логирования и метаданных:</b> IP не логируется и метаданные отдельно не хранятся, что затрудняет поиск и опредиление человека</li>
                        <li><b>открытый код на GitHub:</b>https://github.com/Impisre-software/CrossEra-Messenger/blob/main/index.php</li>
                    </ul>
                    <p style="font-size:11px;">Связь: <b>mindindevin@gmail.com<?php ?></b></p>
                    <div style="text-align:center; font-size:10px; color:#999; margin-top:30px;">
                        Powered by Impisre Software<br>
                        &copy; <?php echo date('Y'); ?>
                    </div>
                </div>

            <?php elseif($view == 'chat'): ?>
                <div id="chat">
                    <?php if(file_exists($curF)) {
                        $lines = file($curF);
                        foreach($lines as $idx => $l) {
                            if(strpos($l, '<?php') !== false) continue;
                            $d = explode('|', trim($l)); if(count($d) < 3) continue; 
                            $uid = $d[3] ?? ''; $msgID = md5($l);
                            ?>
                            <div class="m">
                                <?php echo get_avatar_html($uid, $d[0]); ?>
                                <b><?php echo $d[0]; ?></b>
                                <?php if($uid && $uid != $myU): ?>
                                    <a href="?add_c=<?php echo $uid; ?>&n=<?php echo urlencode($d[0]); ?>" style="font-size:9px; color:#2aa198; text-decoration:none; border:1px solid; padding:0 2px;">+контакт</a>
                                <?php endif; ?>
                                <small style="float:right; opacity:0.5;"><?php echo $d[2]; ?></small><br>
                                <div style="margin-left:29px;"><?php echo parse_msg(v_crypt($d[1], $crypto_key, 'dec')); ?></div>
                                <div class="reac-bar">
                                    <?php 
                                    $rf = $reacDir . $msgID . ".db.php";
                                    if(file_exists($rf)) {
                                        $rcs = file($rf); $counts = [];
                                        foreach($rcs as $rl) {
                                            if(strpos($rl, '<?php') !== false) continue;
                                            $rd = explode('|', trim($rl));
                                            if(isset($rd[2])) $counts[$rd[2]] = ($counts[$rd[2]] ?? 0) + 1;
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
                <form method="POST" enctype="multipart/form-data" style="padding:8px; background:#ddd; border-top:1px solid #bbb; flex-shrink:0;">
                    <textarea name="msg" style="width:95%; height:40px; border:1px solid #999; border-radius:3px; padding:5px;" placeholder="Сообщение..."></textarea>
                    <div style="margin-top:5px; display:flex; justify-content:space-between; align-items:center;">
                        <input type="file" name="f" style="font-size:10px; width:60%;">
                        <input type="submit" name="send_msg" value=">>" class="btn">
                    </div>
                </form>

            <?php elseif($view == 'contacts'): ?>
                <div style="padding:15px; background:#fff; flex:1; overflow-y:auto;">
                    <h3>Мои контакты</h3>
                    <?php if(file_exists($myContactsF)): 
                        foreach(file($myContactsF) as $l): if(strpos($l,'<?php')!==false)continue; $c=explode('|',trim($l)); 
                        $pm = ($myU < $c[0]) ? "pm_{$myU}_{$c[0]}" : "pm_{$c[0]}_{$myU}"; ?>
                        <div class="mod-card">
                            <?php echo get_avatar_html($c[0], $c[1]); ?> <b><?php echo $c[1]; ?></b>
                            <a href="?view=chat&to=<?php echo $pm; ?>" class="btn" style="float:right;">Написать</a>
                        </div>
                    <?php endforeach; else: echo "Пусто"; endif; ?>
                </div>

            <?php elseif($view == 'profile'): ?>
                <div style="padding:15px; background:#fff; flex:1; text-align:center;">
                    <h3>Настройки</h3>
                    <?php echo get_avatar_html($myU, $myN); ?><br><b><?php echo $myN; ?></b><hr>
                    <form method="POST" enctype="multipart/form-data">
                        <input type="file" name="ava_file"><br><br>
                        <input type="submit" name="up_ava" value="Обновить" class="btn">
                    </form>
                </div>

            <?php elseif($view == 'groups'): ?>
                <div style="padding:15px; background:#fff; flex:1; overflow-y:auto;">
                    <h3>Группы</h3>
                    <form method="POST" style="background:#eee; padding:10px; border-radius:5px;">
                        <input name="r_name" required placeholder="Имя" size="10">
                        <select name="r_type"><option value="group">Группа</option><option value="channel">Канал</option></select>
                        <input type="submit" name="create_room" value="+" class="btn">
                    </form><hr>
                    <?php if(file_exists($groupsF)) foreach(file($groupsF) as $l): if(strpos($l,'<?php')!==false)continue; $g=explode('|',trim($l)); ?>
                        <div class="mod-card"><b><?php echo ($g[2]=='channel'?'📢':'👥'); ?> <?php echo $g[1]; ?></b><a href="?view=chat&to=group_<?php echo $g[0]; ?>" class="btn" style="float:right;">Войти</a></div>
                    <?php endforeach; ?>
                </div>

            <?php elseif($view == 'mod_store'): ?>
                <div style="padding:15px; background:#fff; flex:1; overflow-y:auto;">
                    <h3>Магазин</h3>
                    <?php foreach(glob($modDir."*.php") as $f): $fn=basename($f,'.php'); $inst=in_array($fn,$myEnabledMods); ?>
                        <div class="mod-card">🧩 <?php echo $fn; ?><a href="<?php echo $inst ? "?toggle_my_mod=$fn" : "?view=mod_store&pre_inst=$fn"; ?>" class="btn" style="float:right; background:<?php echo $inst?'#dc322f':'#2aa198';?>"><?php echo $inst?'Удалить':'Ставить';?></a></div>
                    <?php endforeach; ?>
                </div>

            <?php elseif(strpos($view, 'run_') === 0): ?>
                <div style="padding:10px; background:#fff; flex:1; overflow-y:auto;">
                    <?php $mName=str_replace('run_','',$view); if(file_exists($modDir.$mName.".php")){ include_once($modDir.$mName.".php"); $f="mod_".$mName."_main"; if(function_exists($f)) $f($myU, $adminID); } ?>
                </div>
            <?php endif; ?>
        </div>
    <?php endif; ?>
</div>
<script>var c=document.getElementById('chat');if(c)c.scrollTop=c.scrollHeight;</script>
</body>
</html>
