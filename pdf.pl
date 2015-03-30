#!/usr/bin/perl
use CAM::PDF;

my $pdf = CAM::PDF->new($filename);
my $pageone_tree = $pdf->getPageContentTree(1);
print CAM::PDF::PageText->render($pageone_tree);

