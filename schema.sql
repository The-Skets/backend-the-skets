create table if not exists comments
(
    id             int auto_increment
        primary key,
    username       longtext not null,
    comment_body   longtext not null,
    video_id       longtext not null,
    date_posted    longtext not null,
    performance_id longtext not null
);

create table if not exists performances
(
    id            int auto_increment
        primary key,
    url_name      longtext not null,
    friendly_name longtext not null,
    image_src     longtext not null,
    date_of_event longtext not null,
    quality       longtext not null
);

create table if not exists users
(
    id            int auto_increment
        primary key,
    username      longtext not null,
    password_hash longtext not null,
    email         longtext not null,
    account_type  longtext not null,
    date_joined   longtext not null,
    pfp_url       longtext not null
);

create table if not exists videos
(
    id             int auto_increment
        primary key,
    performance_id longtext not null,
    friendly_name  longtext not null,
    url_name       longtext not null,
    src            longtext not null,
    thumbnail_url  longtext not null,
    length         longtext not null
);