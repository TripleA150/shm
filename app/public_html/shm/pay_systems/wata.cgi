#!/usr/bin/perl

# Интеграция с WATA (wata.pro)
# Документация: https://wata.pro/api

use v5.14;
use Core::Base;
use LWP::UserAgent ();
use Core::Utils qw(
    passgen
    encode_json
    decode_json
);
use MIME::Base64;
use CGI;
use Crypt::OpenSSL::RSA;

our $cgi = CGI->new;

use SHM qw(:all);
our %vars = parse_args();

if ( $vars{action} eq 'create' ) {
    my $user;
    if ( $vars{user_id} ) {
        $user = SHM->new( user_id => $vars{user_id} );

        if ( $vars{message_id} ) {
            get_service('Transport::Telegram')->deleteMessage( message_id => $vars{message_id} );
        }
    } else {
        $user = SHM->new();
    }

    my $config = get_service('config', _id => 'pay_systems');
    my $api_key = $config->get_data->{wata}->{api_key};
    my $currency = $config->get_data->{wata}->{currency} || 'RUB';
    my $description = $config->get_data->{wata}->{description};
    my $return_url = $config->get_data->{wata}->{return_url};

    $description ||= $vars{description};

    unless ($api_key) {
        print_json({ status => 400, msg => 'Error: api_key required. Please set it in config' });
        exit 0;
    }

    unless ($description) {
        print_json({ status => 400, msg => 'Error: description required. Please set it in config' });
        exit 0;
    }

    $vars{amount} ||= 100;

    my $browser = LWP::UserAgent->new( timeout => 10 );

    my $req = HTTP::Request->new( POST => "https://api.wata.pro/api/h2h/links" );
    $req->header('Content-type' => 'application/json');
    $req->header('Authorization' => "Bearer $api_key");
    $req->header('User-Agent' => 'SHM');
    $req->content( encode_json(
        {
            amount => $vars{amount},
            currency => $currency,
            description => sprintf("%s [%d]", $description, $user->id ),
            orderId => $vars{user_id},
            successRedirectUrl => $return_url,

        }
    ));

    my $response = $browser->request( $req );

    logger->dump( $response->request );
    logger->dump( $response->content );

    if ( $response->is_success ) {
        my $response_data = decode_json( $response->decoded_content );
        if ( my $location = $response_data->{url} ) {
            print_header(
                location => $location,
                status => 301,
            );
        } else {
            print_json( { status => 200, msg => "Payment link created" } );
        }
    } else {
        print_header( status => $response->code );
        print $response->content;
    }
    exit 0;
}


my $body = $cgi->param('POSTDATA');

unless ($body) {
    logger->error("CRITICAL: POSTDATA is empty or not available!");
    print_json({ status => 400, msg => 'Error: no POST data' });
    exit 0;
}


# logger->debug("Raw POST body length: " . length($body));
# logger->debug("Raw POST body preview: " . substr($body, 0, 500));

my $body_copy = $body;

my $signature = $cgi->http('X-Signature');
unless ($signature) {
    logger->error("X-Signature header is missing in request");
    print_json({ status => 400, msg => 'Error: X-Signature header missing' });
    exit 0;
}

my $public_key_pem = get_wata_public_key();
unless ($public_key_pem) {
    logger->error("Failed to fetch public key from WATA API");
    print_json({ status => 500, msg => 'Error: cannot fetch public key' });
    exit 0;
}

my $signature_valid = verify_rsa_signature($body_copy, $signature, $public_key_pem);

unless ($signature_valid) {
    logger->error("❌ Signature verification failed for real");
    print_json({ status => 400, msg => 'Error: signature verification failed' });
    exit 0;
}

logger->info("✅ WATA webhook signature verified successfully");

my $webhook_data;
eval {
    $webhook_data = decode_json($body_copy);
};
if ($@) {
    logger->error("❌ JSON decode failed: $@");
    logger->error("❌ Raw body that failed to parse: [$body_copy]");
    print_json({ status => 400, msg => 'Error: invalid JSON' });
    exit 0;
}

logger->info("✅ JSON parsed successfully");
logger->info("📥 Received webhook " . encode_json($webhook_data));

unless ($webhook_data->{transactionStatus} && $webhook_data->{transactionStatus} eq 'Paid') {
    logger->info("ℹ️ Transaction not paid: " . $webhook_data->{transactionStatus});
    print_json({ 
        status => 200, 
        msg => 'Transaction not paid', 
        transactionStatus => $webhook_data->{transactionStatus} || 'undefined' 
    });
    exit 0;
}

my $user_id = $webhook_data->{orderId};
my $amount = $webhook_data->{amount};

logger->info("🔍 Extracted orderId: [$user_id] (type: " . ref($user_id) . ")");

unless ($user_id) {
    logger->error("❌ Missing orderId in webhook");
    print_json({ status => 400, msg => 'Error: orderId is missing' });
    exit 0;
}

if ($user_id =~ /^\d+$/) {
    $user_id = int($user_id);
    logger->info("🔢 Converted orderId to number: $user_id");
}

my $user = SHM->new( skip_check_auth => 1 );
unless ( $user = $user->id( $user_id ) ) {
    logger->error("❌ User [$user_id] not found in database");
    print_json( { status => 404, msg => "User [$user_id] not found" } );
    exit 0;
}

unless ( $user->lock( timeout => 10 )) {
    logger->error("User [$user_id] is locked, cannot process payment");
    print_json( { status => 408, msg => "The service is locked. Try again later" } );
    exit 0;
}

eval {
    $user->payment(
        user_id => $user_id,
        money => $amount,
        pay_system_id => 'wata',
        comment => $webhook_data,
        uniq_key => $webhook_data->{transactionId},
    );
    $user->commit;
    # logger->info("💰 Payment successful for user [$user_id], amount: $amount RUB");
};
if ($@) {
    logger->error("❌ Failed to process payment for user [$user_id]: $@");
    print_json({ status => 500, msg => 'Internal server error during payment processing' });
    exit 0;
}

print_json( { status => 200, msg => "payment successful" } );
exit 0;


sub get_wata_public_key {
    state $cached_key;
    state $last_fetch_time;
    
    if ($cached_key && $last_fetch_time && (time() - $last_fetch_time) < 3600) {
        return $cached_key;
    }
    
    my $browser = LWP::UserAgent->new(timeout => 10);
    my $response = $browser->get('https://api.wata.pro/api/h2h/public-key');
    
    if ($response->is_success) {
        my $data = decode_json($response->decoded_content);
        if ($data && $data->{value}) {
            $cached_key = $data->{value};
            $last_fetch_time = time();
            logger->info("🔑 Public key fetched and cached successfully");
            return $cached_key;
        } else {
            logger->error("Public key not found in response: " . $response->decoded_content);
        }
    } else {
        logger->error("Failed to fetch public key: " . $response->status_line);
    }
    
    return undef;
}

sub verify_rsa_signature {
    my ($message, $signature, $public_key_pem) = @_;
    
    my $is_valid = 0;
    eval {
        my $rsa = Crypt::OpenSSL::RSA->new_public_key($public_key_pem);
        $rsa->use_sha512_hash();
        
        my $decoded_signature = decode_base64($signature);
        
        $is_valid = $rsa->verify($message, $decoded_signature);
        
        if ($is_valid) {
            logger->debug("✅ RSA signature verified successfully");
        } else {
            logger->debug("❌ RSA signature verification returned false");
        }
    };
    
    if ($@) {
        logger->error("❌ RSA verification error: $@");
        return 0;
    }
    
    return $is_valid ? 1 : 0;
}
