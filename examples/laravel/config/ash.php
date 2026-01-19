<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Default Security Mode
    |--------------------------------------------------------------------------
    |
    | The default security mode for ASH contexts when not specified.
    | Options: 'minimal', 'balanced', 'strict'
    |
    */

    'default_mode' => env('ASH_DEFAULT_MODE', 'balanced'),

    /*
    |--------------------------------------------------------------------------
    | Redis Key Prefix
    |--------------------------------------------------------------------------
    |
    | The prefix used for ASH context keys in Redis.
    |
    */

    'key_prefix' => env('ASH_KEY_PREFIX', 'ash:ctx:'),

    /*
    |--------------------------------------------------------------------------
    | Default TTL
    |--------------------------------------------------------------------------
    |
    | Default time-to-live for contexts in milliseconds.
    |
    */

    'default_ttl_ms' => env('ASH_DEFAULT_TTL_MS', 30000),

    /*
    |--------------------------------------------------------------------------
    | Protected Routes
    |--------------------------------------------------------------------------
    |
    | Routes that should be automatically protected by ASH.
    | Use route patterns or explicit paths.
    |
    */

    'protected_routes' => [
        'api/update',
        'api/profile',
        'api/transactions/*',
    ],

];
