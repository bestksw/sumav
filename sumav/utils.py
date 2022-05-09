'''
Utilities
'''
# Default packages
import os
import re
import logging

# 3rd-party packages

# Internal packages

logger = logging.getLogger(__name__)


def explore_dir(file_or_dir_paths, include_dir=False):
    '''Get directories and their files recursively
    :param list_or_str file_or_dir_paths: directory or file paths
    :param bool include_dir: With directory paths
    :return: list of file paths
    :rtype: list of str
    '''
    here = os.path.abspath(os.path.dirname('.')) + '/'

    if type(file_or_dir_paths) != list:
        file_or_dir_paths = [file_or_dir_paths]

    paths = []
    for file_or_dir_path in file_or_dir_paths:
        # Change relative path to absolute
        if not os.path.isabs(file_or_dir_path):
            file_or_dir_path = here + file_or_dir_path

        # Start explore directory
        if os.path.isdir(file_or_dir_path):
            if include_dir:
                paths.append(file_or_dir_path)

            for base_dir, dir_names, file_names in os.walk(file_or_dir_path):
                if include_dir:
                    for dir_name in dir_names:  # Add directory path
                        paths.append(os.path.join(base_dir, dir_name))

                for file_name in file_names:  # Add file path
                    paths.append(os.path.join(base_dir, file_name))

        elif os.path.isfile(file_or_dir_path):
            paths.append(file_or_dir_path)

    return paths


def make_tokens(detection_names, remove_duplicate=True):
    tokens = []
    tkn_ptn = re.compile("^[a-z]+[0-9]{0,2}[a-z]*$")
    hash_ptn = re.compile("^[0-9a-f]+$")

    for detection_name in detection_names:
        if detection_name is None:
            continue

        for token in re.split("[^0-9a-z]", detection_name.lower()):
            mch = tkn_ptn.match(token)
            if mch:
                token = mch.group()
            else:
                continue

            if len(token) < 4 or len(token) > 30:
                continue
            elif token.isdecimal():
                continue
            elif hash_ptn.match(token):
                continue
            else:
                tokens.append(token)

    if remove_duplicate:
        return sorted(set(tokens))
    else:
        return tokens


def tp_fp_fn(CORRECT_SET, GUESS_SET):
    """
    INPUT: dictionary with the elements in the cluster from the ground truth
    (CORRECT_SET) and dictionary with the elements from the estimated cluster
    (ESTIMATED_SET).

    OUTPUT: number of True Positives (elements in both clusters), False
    Positives (elements only in the ESTIMATED_SET), False Negatives (elements
    only in the CORRECT_SET).
    """
    tp = 0
    fp = 0
    fn = 0
    for elem in GUESS_SET:
        # True Positives (elements in both clusters)
        if elem in CORRECT_SET:
            tp += 1
        else:
            # False Positives (elements only in the "estimated cluster")
            fp += 1
    for elem in CORRECT_SET:
        if elem not in GUESS_SET:
            # False Negatives (elements only in the "correct cluster")
            fn += 1
    return tp, fp, fn


def eval_precision_recall_fmeasure(GROUNDTRUTH_DICT, ESTIMATED_DICT):
    """
    INPUT: dictionary with the mapping "element:cluster_id" for both the ground
    truth and the ESTIMATED_DICT clustering.

    OUTPUT: average values of Precision, Recall and F-Measure.
    """
    # eval: precision, recall, f-measure
    tmp_precision = 0
    tmp_recall = 0

    # build reverse dictionary of ESTIMATED_DICT
    rev_est_dict = {}
    for k, v in ESTIMATED_DICT.items():
        if v not in rev_est_dict:
            rev_est_dict[v] = {k}
        else:
            rev_est_dict[v].add(k)

    # build reverse dictionary of GROUNDTRUTH_DICT
    gt_rev_dict = {}
    for k, v in GROUNDTRUTH_DICT.items():
        if v not in gt_rev_dict:
            gt_rev_dict[v] = {k}
        else:
            gt_rev_dict[v].add(k)

    counter, l = 0, len(ESTIMATED_DICT)

    logger.info('Calculating precision and recall\n')

    # For each element
    for element in ESTIMATED_DICT:
        # Print progress
        if counter % 10000 == 9999:
            logger.info('\r%d out of %d' % (counter, l))
        counter += 1

        # Get elements in the same cluster (for "ESTIMATED_DICT cluster")
        guess_cluster_id = ESTIMATED_DICT[element]

        # Get the list of elements in the same cluster ("correct cluster")
        correct_cluster_id = GROUNDTRUTH_DICT[element]

        # Calculate TP, FP, FN
        tp, fp, fn = tp_fp_fn(gt_rev_dict[correct_cluster_id],
                              rev_est_dict[guess_cluster_id])

        # tmp_precision
        p = 1.0*tp/(tp+fp)
        tmp_precision += p
        # tmp_recall
        r = 1.0*tp/(tp+fn)
        tmp_recall += r
    logger.info('\r%d out of %d\n' % (counter, l))
    precision = 100.0*tmp_precision/len(ESTIMATED_DICT)
    recall = 100.0*tmp_recall/len(ESTIMATED_DICT)
    fmeasure = (2*precision*recall)/(precision+recall)
    return precision, recall, fmeasure
