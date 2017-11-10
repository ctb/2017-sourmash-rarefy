#! /usr/bin/env python
import argparse
import random
import csv

import sourmash_lib
from sourmash_lib import sourmash_args
from sourmash_lib.logging import notify
from sourmash_lib.lca import lca_utils
from sourmash_lib.lca.lca_utils import debug, set_debug


def main():
    p = argparse.ArgumentParser()
    p.add_argument('sigs', nargs='+')
    p.add_argument('--traverse-directory', action='store_true',
                   help='load all signatures underneath directories.')
    p.add_argument('-k', '--ksize', default=31, type=int)
    p.add_argument('-d', '--debug', action='store_true')
    p.add_argument('-f', '--force', action='store_true')
    p.add_argument('--scaled', type=float, default=10000)
    p.add_argument('--plot', default=None)
    p.add_argument('-o', '--output', type=argparse.FileType('wt'),
                   help='CSV output')
    p.add_argument('--step', type=int, default=1000)
    p.add_argument('--repeat', type=int, default=5)
    p.add_argument('--db', nargs='+', action='append')
    args = p.parse_args()

    if args.debug:
        set_debug(args.debug)

    args.scaled = int(args.scaled)

    dblist = []
    known_hashes = set()
    if args.db:
        args.db = [item for sublist in args.db for item in sublist]
        dblist, ksize, scaled = lca_utils.load_databases(args.db, args.scaled)
        assert ksize == args.ksize
        notify('loaded {} LCA databases', len(dblist))

        for db in dblist:
            known_hashes.update(db.hashval_to_lineage_id.keys())
        notify('got {} known hashes!', len(known_hashes))
    
    notify('finding signatures...')
    if args.traverse_directory:
        yield_all_files = False           # only pick up *.sig files?
        if args.force:
            yield_all_files = True
        inp_files = list(sourmash_args.traverse_find_sigs(args.sigs,
                                                          yield_all_files=yield_all_files))
    else:
        inp_files = list(args.sigs)

    n = 0
    total_n = len(inp_files)
    sigs = []
    total_hashvals = list()
    for filename in inp_files:
        n += 1
        for sig in sourmash_lib.load_signatures(filename, ksize=args.ksize):
            notify(u'\r\033[K', end=u'')
            notify('... loading signature {} (file {} of {})', sig.name()[:30], n, total_n, end='\r')
            debug(filename, sig.name())

            sig.minhash = sig.minhash.downsample_scaled(args.scaled)

            total_hashvals.extend(sig.minhash.get_mins())
            sigs.append(sig)
    
    notify(u'\r\033[K', end=u'')
    notify('...found {} signatures total in {} files.', len(sigs), total_n)

    distinct_hashvals = set(total_hashvals)
    notify('{} distinct out of {} total hashvals.', (len(distinct_hashvals)), len(total_hashvals))
    if known_hashes:
        n_known = len(known_hashes.intersection(distinct_hashvals))
        notify('{} of them known, or {:.1f}%', n_known, n_known / float(len(distinct_hashvals)) * 100)

    x = []
    y = []
    z = []
    notify('subsampling...')
    for n in range(0, len(total_hashvals), args.step):
        notify(u'\r\033[K', end=u'')
        notify('... {} of {}', n, len(total_hashvals), end='\r')        
        avg = 0
        known = 0
        for j in range(0, args.repeat):
            subsample = random.sample(total_hashvals, n)
            distinct = len(set(subsample))
            if known_hashes:
                known += len(set(subsample).intersection(known_hashes))
            avg += distinct

        x.append(n)
        y.append(avg / args.repeat)
        z.append(known / args.repeat)

    notify('\n...done!')

    if args.output:
        w = csv.writer(args.output)
        w.writerow(['n', 'k', 'known'])
        for a, b, c in zip(x, y, z):
            w.writerow([a, b, c])

    if args.plot:
        from matplotlib import pyplot
        pyplot.plot(x, y)
        pyplot.savefig(args.plot)
        

if __name__ == '__main__':
    main()
