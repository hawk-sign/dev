#!/usr/bin/python3
import glob
import os
import sys
import re

# Change directory to the ./tools directory
os.chdir(os.path.dirname(os.path.abspath(__file__)))

targets = dict({
    'ref': { 'name': 'Reference', 'loc': './Reference_Implementation', 'locnist': './NIST/Reference_Implementation/hawk%d/', 'avx2': False },
    'avx2': { 'name': 'AVX2 optimized', 'loc': './Optimized_Implementation/avx2', 'locnist': './NIST/Optimized_Implementation/avx2/hawk%d/', 'avx2': True }
})

# Algorithm parameters (indexed by logn)
zSECRETKEYBYTES = [ '', '', '', '', '', '', '', '',  '96',  '184',  '360' ]
zPUBLICKEYBYTES = [ '', '', '', '', '', '', '', '', '450', '1024', '2440' ]
zCRYPTOBYTES    = [ '', '', '', '', '', '', '', '', '249',  '555', '1221' ]

def build(target):
    name = targets[target]['name']
    print(f'Building {name} implementation...')
    files = glob.glob('./src/*.[c|h]')
    filesNIST = glob.glob('./extra/*')

    avx2 = targets[target]['avx2']
    # Toggle, if we should print, depending on AVX2 being used or not:
    printAVX2 = True

    # Note: '#ifdef' and '#ifndef' are matched as a '#if'; this is used for
    # the internal headers (ng_config.h, ng_inner.h and hawk_inner.h) only.
    # All other uses systematically employ a '#if'
    re_if = re.compile('#if (HAWK_AVX2|NTRUGEN_AVX2)')
    re_else = re.compile('#else // (HAWK_AVX2|NTRUGEN_AVX2)')
    re_endif = re.compile('#endif // (HAWK_AVX2|NTRUGEN_AVX2)')
    re_autoconf = re.compile('#ifndef (HAWK_AVX2|NTRUGEN_AVX2)')

    for inputFile in files:
        # Chop away './src' part
        outputFile = targets[target]['loc'] + inputFile[5:]

        # hawk_config.h gets a special treatment since options are
        # internalized.
        if inputFile[6:] == 'hawk_config.h':
            with open(outputFile, 'w') as g:
                print('#ifndef HAWK_CONFIG_H__', file=g)
                print('#define HAWK_CONFIG_H__', file=g)
                print('#define HAWK_PREFIX   hawk', file=g)
                print('#endif', file=g)
            continue

        seen_blank = False
        suppress_autoconf = False
        with open(inputFile, 'r') as f:
            with open(outputFile, 'w') as g:
                for line in f:
                    # The autoconfiguration block is removed.
                    if re_autoconf.match(line):
                        suppress_autoconf = True
                        continue
                    elif suppress_autoconf:
                        if re_endif.match(line):
                            suppress_autoconf = False
                        continue

                    if re_if.match(line):
                        printAVX2 = avx2
                    elif re_else.match(line):
                        printAVX2 = not avx2
                    elif re_endif.match(line):
                        printAVX2 = True
                    elif printAVX2:
                        # Print this line iff the mode matches the target.
                        # In non-AVX2 code, we suppress the emission of
                        # TARGET_AVX2 and ALIGNED_AVX2. Also, we coalesce
                        # sequences of blank lines.
                        sline = line.strip()
                        if not avx2:
                            if (sline == 'TARGET_AVX2'
                                or sline == 'TARGET_AVX2_ONLY'
                                or sline == 'ALIGNED_AVX2'):
                                continue
                            if sline == 'MQ_UNUSED TARGET_AVX2':
                                line = 'MQ_UNUSED\n'
                        if sline == '':
                            if seen_blank:
                                continue
                            else:
                                seen_blank = True
                        else:
                            seen_blank = False
                        g.write(line)

    # Make packages for NIST submission.
    for logn in range(8, 11):
        # Output directy name uses the polynomial degree.
        n = 1 << logn
        ddir = targets[target]['locnist'] % n

        # Make sure the directory exists.
        os.makedirs(ddir, exist_ok=True)

        # Copy the files that have been just generated for this target.
        for srcFile in files:
            inputFile = targets[target]['loc'] + srcFile[5:]
            outputFile = ddir + srcFile[5:]
            with open(inputFile, 'r') as f:
                with open(outputFile, 'w') as g:
                    for line in f:
                        g.write(line)

        # Also copy the extra NIST files, replacing the 'zzz' constructs
        # with the appropriate values.
        zLOGN = '%d' % logn
        zN = '%d' % n
        for inputFile in filesNIST:
            outputFile = ddir + inputFile[7:]
            with open(inputFile, 'r') as f:
                with open(outputFile, 'w') as g:
                    for line in f:
                        if line.find('zzz') >= 0:
                            line = line.replace('zzzSECRETKEYBYTES', zSECRETKEYBYTES[logn])
                            line = line.replace('zzzPUBLICKEYBYTES', zPUBLICKEYBYTES[logn])
                            line = line.replace('zzzCRYPTOBYTES', zCRYPTOBYTES[logn])
                            line = line.replace('zzzLOGN', zLOGN)
                            line = line.replace('zzzN', zN)
                        g.write(line)

for target in targets:
    if (len(sys.argv) == 1 or target in sys.argv):
        build(target)
