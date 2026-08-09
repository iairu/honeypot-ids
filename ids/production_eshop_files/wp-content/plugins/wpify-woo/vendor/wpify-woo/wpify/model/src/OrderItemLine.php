<?php

declare (strict_types=1);
namespace WpifyWooDeps\Wpify\Model;

use WC_Product;
use WpifyWooDeps\Wpify\Model\Attributes\AccessorObject;
class OrderItemLine extends OrderItem
{
    /**
     * WC Product.
     */
    #[AccessorObject]
    public ?WC_Product $product = null;
    /**
     * Product ID.
     */
    #[AccessorObject]
    public int $product_id = 0;
    /**
     * Variation ID.
     */
    #[AccessorObject]
    public int $variation_id = 0;
}
