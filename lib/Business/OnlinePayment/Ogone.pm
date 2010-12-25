package Business::OnlinePayment::Ogone;
use parent 'Business::OnlinePayment::HTTPS';
use strict; # keep Perl::Critic happy over common::sense;
use common::sense;
use Carp;
use Data::Dumper;
use XML::Simple qw/:strict/;
use Digest::SHA qw/sha1_hex sha256_hex sha512_hex/;
use MIME::Base64;

# ABSTRACT: Online payment processing via Ogone
our $VERSION = 0.01;
our $API_VERSION = 3.5;

# Ogone config defaults and info ######################################################################################

our %defaults = (
    server => 'secure.ogone.com',
    port => 443,
);

our %info = (
    'info_compat'           => '0.01', # always 0.01 for now,
    'gateway_name'          => 'Ogone',
    'gateway_url'           => 'http://www.ogone.com/',
    'module_version'        => $VERSION,
    'supported_types'       => [ qw( CC ) ],
    'token_support'         => 0, #card storage/tokenization support
    'test_transaction'      => 1, #set true if ->test_transaction(1) works
    'supported_actions'     => [
        'Authorization Only',
        'Post Authorization',
        'Query',
        'Credit',
    ],
);

# Methods #############################################################################################################

sub _info { 
    return \%info;
}

sub set_defaults {
    my $self = shift;
    my %data = @_;
    $self->{$_} = $defaults{$_} for keys %defaults;

    $self->build_subs(qw/http_args result_xml/);
}


sub submit {
    my $self = shift;
    my %data = $self->content();

    # do not allow submitting same object twice
    croak 'submitting same object twice is not allowed' if $self->{_dirty}; $self->{_dirty} = 1;

    # Turn the data into a format usable by the online processor
    croak 'no action parameter defined in content' unless exists $self->{_content}->{action};

    # Default currency to Euro
    $self->{_content}->{currency} ||= 'EUR';

    # Table to translate from Business::OnlinePayment::Ogone args to Ogone API args
    # The values of this hash are also used as a list of allowed args for the HTTP POST request, thus preventing information leakage
    my %ogone_api_args = (
        # credentials
        login   => 'USERID',
        password => 'PSWD',
        PSPID   => 'PSPID',
        
        # primary identifier
        invoice_number => 'orderID',
        
        # transaction identifiers (action = query)
        payid => 'PAYID',
        payidsub => 'PAYIDSUB',
        
        # credit card data
        card_number => 'CARDNO', 
        cvc => 'CVC',
        expiration => 'ED',
        alias => 'ALIAS',
        
        # financial data
        currency => 'Currency',
        amount => 'amount',
        
        # Ogone specific arguments
        operation => 'Operation',       # REN, DEL, DES, SAL, SAS, RFD, RFS
        eci => 'ECI',                   # defaults 7: e-commerce with ssl (9: recurring e-commerce)
        accepturl => 'accepturl',
        declineurl => 'declineurl',
        exceptionurl => 'exceptionurl',
        paramplus => 'paramplus',
        complus => 'complus',
        language => 'LANGUAGE',

        # Business::OnlinePayment common
        description => 'COM',
        name => 'CN',
        email => 'EMAIL',
        address => 'Owneraddress',
        zip => 'OwnerZip',
        city => 'ownertown',
        country => 'ownercty',
        phone => 'ownertelno',

        # client authentication (not used directly, only here as valid HTTP POST arg)
        SHASign => 'SHASign',           # see sha_key, sha_type
        
        # 3d secure arguments
        flag3d => 'FLAG3D',
        win3ds => 'win3ds',
        http_accept => 'HTTP_ACCEPT',
        http_user_agent => 'HTTP_USER_AGENT',


    );

    # Only allow max of 2 digits after comma as we need to int ( $amount * 100 ) for Ogone
    croak 'max 2 digits after comma (or dot) allowed' if $self->{_content}->{amount} =~ m/[\,\.]\d{3}/;

    # Ogone has multiple users per login, defaults to login
    $self->{_content}->{PSPID}      ||= $self->{PSPID} || $self->{login} || $self->{_content}->{login};

    # Login information, default to constructor values
    $self->{_content}->{login}      ||= $self->{login};
    $self->{_content}->{password}   ||= $self->{password};
    $self->{_content}->{PSPID}      ||= $self->{PSPID};

    # Default Operation request for authorization (RES) for authorization only, (capture full and close) SAS for post authorization
    $self->{_content}->{operation}  ||= 'RES' if $self->{_content}->{action} =~ m/authorization only/;
    $self->{_content}->{operation}  ||= 'SAS' if $self->{_content}->{action} =~ m/post authorization/;

    # Default ECI is SSL e-commerce (7)
    $self->{_content}->{eci}        ||= 7;

    # Remap the fields to their Ogone-API counterparts ie: cvc => CVC
    $self->remap_fields(%ogone_api_args);

    croak "no sha_key provided" if $self->{_content}->{sha_type} && ! $self->{_content}->{sha_key};
        
    # These fields are required by Businiess::OnlinePayment::Ogone
    my @args_basic  = (qw/login password PSPID action/);
    my @args_ccard  = (qw/card_number expiration cvc/);
    my @args_alias  = (qw/alias cvc/);
    my @args_new    = (@args_basic, qw/invoice_number amount currency/, $self->{_content}->{card_number} ? @args_ccard : @args_alias);
    my @args_post   = (@args_basic, qw/invoice_number/);
    my @query       = (@args_basic, qw/invoice_number/);

    # Poor mans given/when
    my %action_arguments = (
        qr/authorization only/i      => \@args_new,
        qr/post authorization/i      => \@args_post,
        qr/query/i                   => \@query
    );

    my @args =  map { @{$action_arguments{$_}} }                # lookup value using regex, return dereffed arrayref
                grep { $self->{_content}->{action} =~ $_ }      # compare action input against regex key
                keys %action_arguments;                         # extract regular expressions

    croak 'unable to determine HTTP POST @args, is the action parameter one of ( authorization only | post authorization | query )' unless @args;

    # Enforce the field requirements by calling parent
    my @undefs = grep { ! defined $self->{_content}->{$_} } @args;
    
    croak "missing required args: ". join(',',@undefs) if scalar @undefs;

    # Your module should check to see if the  require_avs() function returns true, and turn on AVS checking if it does.
    if ( $self->require_avs() ) {
        $self->{_content}->{CHECK_AAV} = 1;
        $self->{_content}->{CAVV_3D} = 1;
    }

    # Define all possible arguments for http request
    my @all_http_args = (values %ogone_api_args);

    # Construct the HTTP POST parameters by selecting the ones which are defined from all_http_args
    my %http_req_args = map { $_ => $self->{_content}{$_} } 
                        grep { defined $self->{_content}{$_} } 
                        map { $ogone_api_args{$_} || $_ } @all_http_args;

    # Ogone accepts the amount as 100 fold in integer form.
    $http_req_args{amount} = int(100 * $http_req_args{amount}) if exists $http_req_args{amount};
   
    # Calculate sha1 by default, but has to be enabled in the Ogone backend to have any effect
    my ($sha_type)  = ($self->{_content}->{sha_type} =~ m/^(1|256|512)$/);

    # Create a reference to the correct sha${sha_type}_hex function, default to SHA-1
    my $sha_hex = sub { my $type = shift; no strict; &{"sha".($type || 1)."_hex"}(@_); use strict; };

    # Algo: make a list of "KEY=value$passphrase" sort alphabetically
    my $signature =  join('',
                         sort map { uc($_) . "=" . $http_req_args{$_} . ($self->{_content}{sha_key} || '') }
                         keys %http_req_args);

    $http_req_args{SHASign} = $sha_hex->($sha_type,$signature);

    # Construct the URL to query, taking into account the action and test_transaction values
    my %action_file = (
        qr/authorization only/i    => 'orderdirect.asp',
        qr/post authorization/i    => 'maintenancedirect.asp',
        qr/query/i                 => 'querydirect.asp',
    );

    my $uri_dir  = $self->test_transaction() ? 'test' : 'prod';
    my ($uri_file) =  map { $action_file{$_} }
                      grep { $self->{_content}->{action} =~ $_ }
                      keys %action_file;

    croak 'unable to determine URI path, is the action parameter one of ( authorization only | post authorization | query )' unless $uri_file;

    $self->{path} = '/ncol/'.$uri_dir.'/'.$uri_file;

    # Save the http args for later inspection
    $self->http_args(\%http_req_args);

    # Submit the transaction to the processor and collect a response.
    my ($page, $response_code, %reply_headers) = $self->https_post(%http_req_args);

    # Call server_response() with a copy of the entire unprocessed response
    $self->server_response([$response_code, \%reply_headers, $page]);

    my $xml = XMLin($page, ForceArray => [], KeyAttr => [] );

    # Store the result xml for later inspection
    $self->result_xml($xml);

    croak 'Ogone refused SHA digest' if $xml->{NCERRORPLUS} =~ m#^unknown order/1/s#;

    # Call is_success() with either a true or false value, indicating if the transaction was successful or not.
    if ( $response_code =~ m/^200/ ) {
        $self->is_success(0); # defaults to fail

        if ( $xml->{STATUS} eq '' ) { $self->is_success(0) }
        else {
            if ( $xml->{STATUS} == 46 ) { $self->is_success(1) } # identification required
            if ( $xml->{STATUS} == 5 )  { $self->is_success(1) } # authorization accepted
            if ( $xml->{STATUS} == 9 )  { $self->is_success(1) } # payment accepted
            if ( $xml->{STATUS} == 91 ) { $self->is_success(1) } # partial payment accepted
            if ( $xml->{STATUS} == 0 )  { $self->is_success(0) } # invalid or incomplete
            if ( $xml->{STATUS} == 0 && $xml->{NCERROR} == 50001134 ) { $self->is_success(0); $self->failure_status('declined') } # 3d secure wrong identification
            if ( $xml->{STATUS} == 2 ) { $self->is_success(0); $self->failure_status('refused') } # authorization refused
        }

    } else { 
        warn "remote server did not respond with HTTP 200 status code";
        $self->is_success(0) 
    }

    # Extract the base64 encoded HTML part
    if ( $xml->{STATUS} == 46 ) {
        my $html = decode_base64($xml->{HTML_ANSWER});
           # remove sillyness
           $html =~ s///g; 
           $html =~ s/ //g;

        # XXX: REMOVE
        open my $fh, '>', '/tmp/ogone_'.$self->{_content}->{win3ds}.'.html';
        print $fh $html;
    }
  
    # Call result_code() with the servers result code
    $self->result_code($xml->{NCERROR});

    # If the transaction was successful, call authorization() with the authorization code the processor provided.
    if ( $self->is_success() ) {
        $self->authorization($xml->{PAYID});
    }

    # If the transaction was not successful, call error_message() with either the processor provided error message, or some error message to indicate why it failed.
    if ( not $self->is_success() and $xml->{NCERRORPLUS} ne '!' ) { # '!' == no errorplus
        $self->error_message($xml->{NCERRORPLUS});
    }
}

42;
__END__

=head1 NAME

Business::OnlinePayment::Ogone - Online payment processing via Ogone

=head1 SYNOPSYS

    use common::sense;
    use Data::Dumper;
    use Business::OnlinePayment;

    my $tx = new Business::OnlinePayment('Ogone', login => 'fred', 
                                                  pspid => 'bedrock_api',
                                                  password => 'fl1nst0ne' );

    $tx->test_transaction(1); # remove when migrating to production env

    $tx->content(
        amount => 23.4,                 # only 2 decimals after . allowed
        currency => 'EUR',              # currency (EUR, USD, GBP, CHF, ...)
        invoice_number => 54321,        # primary transaction identifier
        card_number => 4111111111111111,# you can use this number for testing
        cvc => 432,                     # for testing: /d{3}/
        expiration => 12/15,            # for testing: MM/YY, in the future
        address => 'Somestreet 234',    # optional customer address
        city => 'Brussels',             # optional customer city
        zip => 1000                     # optional customer zip code
        country => 'BE',                # optional customer country (iso?)
        sha_type => 512,                # optional SHA identification (1, 256, 512)
        sha_key => 'a_secret_key',      # required param if sha_type is set
        alias => 'Customer 1',          # store an alias to the card_number
    );

    eval    { $tx->submit() };
    if ($@) { die 'failed to submit to remote because: '.$@ };

    if ( $tx->is_success() ) {
        print 'transaction successful\n';
        print Dumper({
            ogone_ncerror   => $tx->result_code,
            ogone_payid     => $tx->authorization });

    } else {
        print 'transaction unsuccessful: remote has raised an error\n';
        print Dumper({
            ogone_ncerrorplus   => $tx->error_message,
            http_post_args      => $tx->http_args,
            ogone_xml_response  => $tx->result_xml,
            ogone_raw_response  => $tx->server_response });
    }


=head1 THE BIG PICTURE

=head2 Authorize Only, Post Authorize, Refund

         Client                                 Ogone HTTPS      Bank
      ------------------------------------------------------------------------

  1        +---|Authorize Only| orderID=1----------->. [RES]        
                                                     |              
  2        *<---STATUS=5 ----------------------------'                    
  


  3        +---|Post Authorize| orderID=1----------->. [SAL] 
                                                     |
  4        *<---STATUS=91 PAYID=.. PAYIDSUB=.. ------+ (processing)
                                                     |
  5                                                  `----------->.
                                                                  | (processed) +$
  6                                         STATUS=9 .<-----------'
 


  7     .->+---|Query| orderID or PAYID,PAYIDSUB= -->. 
        |                                            |       
        |  .<----------------------------------------'                   
        |  |
  8     STATUS == 9   
           |
  9        `---|Refund| orderID or PAYID,PAYIDSUB= ->. [RFD]
                                                     |
 10        *<-- STATUS=81 ---------------------------+ (processing)
                                                     |
 11                                                  `----------->.
                                                                  | (processed) -$
 12                                         STATUS=8 .<-----------'


=over 1

=item B<1> submit authorize only request usin RES operation with orderID=1. This will reserve the money on the credit card.

=item B<2> STATUS=5 indicates the authorization succeeded.

=item B<3> some time later, you wish to receive/transfer the money to you. You issue a C<post authorize> request (defaults to C<SAL>)

=item B<4> STATUS=91 indicates the payment is being processed. PAYID and PAYIDSUB are references that identify the current operation on the transaction.

=item B<5> Ogone handles processing with your bank

=item B<6> money has been put into your account. STATUS is set to 9

=item B<7> We want to refund a transaction. To check the transaction is refundable, we must first query it.

=item B<8> Refunds are only possible once a transaction is completed (STATUS = 9) (e.g. not while it is processing = 91), thus loop until so.

=item B<9> Request refund using orderID or PAYID and PAYISUB to identify refundable operation.

=item B<10> STATUS=81 indicates the refund is being processed

=item B<11> Ogone handles processing with your bank

=item B<12> Money has been taken from your account. STATUS is set to 8

=back

=head1 PARAMETERS

=over 1

=item action

=item operation

=item sha_type

=item flag3d

=item win3ds

=back

=head1 TODO

=over 1

=item Parse 3d-secure HTML 

=back


=head1 Configuration parameters

Configure the L<Ogone Test Backend|https://secure.ogone.com/ncol/test/frame_ogone.asp> or
L<Ogone Prod Backend|https://secure.ogone.com/ncol/prod/frame_ogone.asp> using the following settings:


=head2 Technical information > Your technical settings > Global security parameters 

=over 1

=item Compose string: Each parameter

=item Hash algorithm: same as C<$sha_type>

=item Character encoding: UTF-8

=back


=head2 Technical information > Your technical settings > Global security parameters 

=over 1

=item SHA-IN Pass phrase: same as C<$sha_key>

=back
