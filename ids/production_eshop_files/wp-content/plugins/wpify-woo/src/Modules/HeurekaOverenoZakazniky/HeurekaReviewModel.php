<?php

namespace WpifyWoo\Modules\HeurekaOverenoZakazniky;

defined( 'ABSPATH' ) || exit;

use WpifyWooDeps\Wpify\Model\Attributes\Column;
use WpifyWooDeps\Wpify\Model\Model;

class HeurekaReviewModel extends Model {
    #[Column( type: Column::INT, auto_increment: true, primary_key: true )]
    public int $id;

    #[Column( type: Column::BIGINT )]
    public int $rating_id;

    #[Column( type: Column::VARCHAR )]
    public string $source;

    // Order date reported by Heureka (unix timestamp as string to keep compatibility)
    #[Column( type: Column::VARCHAR )]
    public string $ordered;

    // Review unix timestamp
    #[Column( type: Column::BIGINT )]
    public int $unix_timestamp;

    // Review main values (stored as strings for simplicity/compatibility)
    #[Column( type: Column::VARCHAR )]
    public string $total_rating;

    #[Column( type: Column::VARCHAR )]
    public string $recommends;

    #[Column( type: Column::VARCHAR )]
    public string $delivery_time;

    #[Column( type: Column::VARCHAR )]
    public string $transport_quality;

    #[Column( type: Column::VARCHAR )]
    public string $communication;

    #[Column( type: Column::VARCHAR )]
    public string $pickup_time;

    #[Column( type: Column::VARCHAR )]
    public string $pickup_quality;

    // Text fields
    #[Column( type: Column::TEXT )]
    public string $pros;

    #[Column( type: Column::TEXT )]
    public string $cons;

    #[Column( type: Column::TEXT )]
    public string $summary;

    #[Column( type: Column::TEXT )]
    public string $reaction;

    #[Column( type: Column::BIGINT )]
    public int $order_id;
}

