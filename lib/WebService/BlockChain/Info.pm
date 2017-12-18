package WebService::BlockChain::Info;
use Moose;
with 'WebService::Client';

use Crypt::Mac::HMAC qw(hmac hmac_hex);
use Function::Parameters;
use HTTP::Request::Common qw(DELETE GET POST PUT);
use Time::HiRes qw(time);

has api_key => (
    is       => 'ro',
    required => 0,
);

has api_secret => (
    is       => 'ro',
    required => 0,
);

has '+base_url' => (
    is      => 'ro',
    default => 'https://blockchain.info/',
);

sub BUILD {
    my ($self) = @_;
    if (defined($self->api_key)) {
    	$self->ua->default_header(':ACCESS_KEY' => $self->api_key);
    }
}

around req => fun($orig, $self, $req, @rest) {
    if (defined($self->api_key)) {
    my $nonce = time * 1e5;
    my $signature =
        hmac_hex 'SHA256', $self->api_secret, $nonce, $req->uri, $req->content;
    $req->header(':ACCESS_NONCE'     => $nonce);
    $req->header(':ACCESS_SIGNATURE' => $signature);
    }
    return $self->$orig($req, @rest);
};

method latestblock { $self->get('latestblock?format=JSON') }

# ABSTRACT: BlockChain (http://BlockChain.info) API bindings

=head1 SYNOPSIS

    use WebService::BlockChain::Info;

    my $bci = WebService::BlockChain::Info->new(
        api_key    => 'API_KEY',
        api_secret => 'API_SECRET',
        logger     => Log::Tiny->new('/tmp/coin.log'), # optional
    );
    my $lastblock = $bci->latestblock();

=head1 METHODS

=head2 latestblock

    latestblock()

Returns the last block mined on the bitcoin network.

=cut

1;
