<?php

return [
    'db' => [
        'connections' => [
            'db1' => [
                'driver' => 'mysql',
                'host' => 'localhost',
                'database' => 'endocore_test',
                'username' => 'endocore',
                'password' => '',
                'charset' => 'utf8', // Optional
                'timezone' => 'Europe/Berlin', // Optional
            ]
        ],

        'default_connection' => 'db1',
    ],

    'auth' => [
        'backend' => 'mysql',

        'backends' => [
            'array' => [
                'users' => [
                    'foo' => '$2y$10$hJpespHOJUYzFtHIQk57OusBdwIOXz.8tUdbb9j545Meh2wmeshMm',
                ]
            ],

            'mysql' => [
                'db_connection' => 'db1',
            ]
        ]
    ]
];
