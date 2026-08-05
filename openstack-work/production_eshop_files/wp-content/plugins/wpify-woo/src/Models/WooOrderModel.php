<?php

namespace WpifyWoo\Models;


defined( 'ABSPATH' ) || exit;

use WpifyWooDeps\Wpify\Model\Attributes\Meta;
use WpifyWooDeps\Wpify\Model\Order;

class WooOrderModel extends Order {
	#[Meta('_billing_ic')]
	private string $ic = '';
	#[Meta('_billing_dic')]
	private string $dic = '';
	#[Meta('_billing_dic_dph')]
	private string $dic_dph = '';
}
