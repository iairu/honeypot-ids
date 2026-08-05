<?php

namespace WpifyWoo\Modules\PricesLog;


defined( 'ABSPATH' ) || exit;

use WpifyWooDeps\Wpify\Model\Attributes\Column;
use WpifyWooDeps\Wpify\Model\Model;

class PricesLogModel extends Model {
	#[Column( type: Column::INT, auto_increment: true, primary_key: true )]
	public int $id;

	#[Column( type: Column::BIGINT )]
	public int $product_id;

	#[Column( type: Column::VARCHAR )]
	public string $regular_price;

	#[Column( type: Column::VARCHAR )]
	public string $sale_price;
	#[Column( type: Column::VARCHAR )]
	public string $created_at;
}
