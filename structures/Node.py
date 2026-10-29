import logging
from collections import defaultdict
from evaluation.get_dep_tree import get_cves_dict
from utils.version_utils import _sort, get_averaged_defaults, get_non_major_vers, get_least_deps_introducing_versions, \
    get_non_dev_vers, get_closest_default, get_other_major_vers, get_upgrade_versions
from utils.db_utils import get_default_version, maven, maven_deps, c, get_all_versions
from utils.graph_api import get_clean_versions, get_vul_versions, get_unreachable_fewest_vul_vers
from exceptions import NoSolutionFound

class Node:
    def __init__(self, gav):
        # set fixed version
        if gav.count('|') == 3:
            gavsp = gav.split('|')
            g,a,v= gavsp[0], gavsp[1], gavsp[3]
        else:
            g, a, v = gav.split('|')
        self.gav = g+'|'+a+'|'+v
        if '[' in gav and ']' in gav and ',' not in gav:
            g, a, v = gav.replace('[', '').replace(']', '').split('|')
            self.original_version = v
            self.preferred = v
            self.candidates = [v]
            self.ga = g + '|' + a
            self.gav = gav.replace('[', '').replace(']', '')
            self.parents = {}
            self.sons = {}
            self.lvl = 0
            self.low_candidates = []
            self.cves = set()
            self.is_backtrack = False
            return

        self.original_version = v
        self.ga = g+'|'+a
        self.gav = gav.replace('[', '').replace(']', '')
        self.sons = {}
        self.candidates = []
        self.preferred = ''
        self.parents = {}
        self.lvl = 0
        self.low_candidates = []
        self.cves = set()
        self.is_backtrack = False
        # set invalid by hard backtrack
        self.hard_incom_vers = set()
        # set invalid by soft backtrack
        self.soft_incom_vers = dict()

    def get_gav(self):
        return self.gav

    def get_ga(self):
        return self.ga

    def set_cves(self, cves):
        self.cves = cves

    def get_original_version(self):
        return self.original_version

    def add_parent(self, parent):
        self.parents[str(parent)] = parent

    def remove_parent(self, parent):
        self.parents.pop(str(parent))

    def get_parents(self):
        return list(self.parents.values())

    def add_son(self, son):
        self.sons[str(son)] = son

    def remove_son(self, son):
        self.sons.pop(str(son))

    def get_sons(self):
        return list(self.sons.values())

    def set_candidates(self, cans):
        cans = _sort(cans)
        self.candidates = cans

    def get_candidates(self):
        return self.candidates

    def set_preferred(self, pre):
        self.preferred = pre.replace('[', '').replace(']', '')

    def get_preferred(self):
        if self.preferred == '':
            return None
        return self.preferred

    def get_preferred_gav(self):
        if self.preferred!='':
            return self.ga+'|'+self.preferred
        else:
            logging.debug('Preferred not set '+self.ga)
            return None

    def set_lvl(self, lvl):
        self.lvl = lvl

    def get_lvl(self):
        return self.lvl

    def get_low_candidates(self):
        return self.low_candidates

    def set_low_candidates(self, cans):
        self.low_candidates = cans

    def get_backtrack(self):
        return self.is_backtrack

    def set_backtrack(self, bt):
        self.is_backtrack = bt

    def get_hard_incom_vers(self):
        return self.hard_incom_vers

    def __str__(self):
        return self.ga

    def __eq__(self, other):
        return other.get_ga()==self.ga

    def __get_highest_parents(self):
        lvl_dict = defaultdict(list)
        for parent in self.parents.values():
            if parent.get_preferred()==None:
                continue
            lvl_dict[parent.get_lvl()].append(parent)
        if len(lvl_dict)==0:
            return []
        return lvl_dict[min(lvl_dict.keys())]


    def get_all_versions(self, c):
        maven = c['library-crawler']['maven']
        vers = []
        g,a = self.ga.split('|')
        for doc in maven.find({'group': g, 'artifact': a}):
            vers.append(doc['version'])
        return vers

    def calculate_candidates_safer(self, c, depGraph):
        # return backtrack
        # default return is false
        maven = None
        if c is not None:
            try:
                maven = c['library-crawler']['maven']
            except Exception:
                maven = None
        ## debug
        # if self.ga=='com.oracle|ojdbc6':
        #     ccc = 1
        ## debug


        if not self.check_central(c):
            self.set_candidates([self.get_original_version()])
            return False

        # Skip the calculated
        if len(self.candidates) > 0 and not self.is_backtrack:
            return False

        clean_versions = get_clean_versions(self.gav, c)

        # if original is clean then stay the same
        if self.get_original_version() in clean_versions:
            self.set_candidates([self.get_original_version()])
            return False

        all_versions = get_all_versions(self.ga, maven)
        # prefer upgrades
        uppers, lowers = get_upgrade_versions(self.original_version, all_versions)
        lowers = []
        # look for non-dev (QM)
        candidates = get_non_dev_vers(uppers, self.original_version)
        # look for minor and patch (QM)
        candidates = get_non_major_vers(c, self.gav, candidates)
        # look for compatible (BP)
        candidates = depGraph.exclude_reachable_incomaptible_versions(c, self.gav, candidates, clean_versions)
        if len(candidates) == 0:
            # look for non-dev (QM)
            candidates = get_non_dev_vers(all_versions, self.original_version)
            # look for minor and patch (QM)
            candidates = get_non_major_vers(c, self.gav, candidates)
            # look for compatible (BP)
            candidates = depGraph.exclude_reachable_incomaptible_versions(c, self.gav, candidates, clean_versions)



        compatible_candidates = candidates
        if len(compatible_candidates)==0:
            return 'hard'

        # Filter out reachable vulnerable versions (BP)

        comp_clean_versions = _sort(list(set(clean_versions).intersection(compatible_candidates)))
        if len(comp_clean_versions) == 0:
            vul_versions = get_vul_versions(self.gav, c, clean_versions)
            cves_dict = get_cves_dict([self.ga + '|' + v for v in vul_versions])
            unreachable_versions, reachable_versions = depGraph.exclude_reachable_vulnerable_versions(
                self.ga, cves_dict, c)
            # look for non-vul (QM)

            candidates = set(get_unreachable_fewest_vul_vers(self.gav, c, unreachable_versions)).intersection(compatible_candidates)

        else:
            candidates = comp_clean_versions

        # look for least dep nodes (QM)
        # candidates = get_least_deps_introducing_versions(c, self.gav, candidates)[0]

        # look for no dependency conflict (BP)
        # if len(candidates) == 0:
        #     candidates = depGraph.exclude_reachable_incomaptible_versions(c, self.gav, clean_versions)

        # if pre-filtered versions have API breaking, then check API breaking first then post-filter
        if len(candidates) == 0:

            candidates = get_unreachable_fewest_vul_vers(self.gav, c, compatible_candidates)
            # If all versions have breaking, then relax secondary objectives
            if len(candidates) == 0:
                # relax major/dev limits
                if len(compatible_candidates) != 0:
                    self.set_candidates(compatible_candidates)
                # backtrack because all constraints broken
                else:
                    # if non compatible, hard backtrack
                    if len(compatible_candidates) == 0:
                        return 'hard'
                    if len(compatible_candidates) == 0:
                        return 'soft'
                # low_candidates_list = depGraph.get_unreachable_vulnerable_versions_by_prioritization(self.ga, c,
                #                                                                                  clean_versions=clean_versions)
                # self.set_low_candidates(low_candidates_list[0])
                # self.set_candidates(low_candidates_list[0])
            else:
                self.set_candidates(candidates)
        else:
            self.set_candidates(candidates)

        return False

    def calculate_candidates(self, c, depGraph):
        # return backtrack
        # default return is false
        maven = c['library-crawler']['maven']
        ## debug
        # if self.ga=='com.oracle|ojdbc6':
        #     ccc = 1
        ## debug
        if not self.check_central(c):
            self.set_candidates([self.get_original_version()])
            return False




        # Skip the calculated
        if len(self.candidates)>0 and not self.is_backtrack:
            return False



        # Filter out reachable vulnerable versions (BP)
        clean_versions = get_clean_versions(self.gav, c)
        if len(clean_versions) ==0:
            vul_versions = get_vul_versions(self.gav, c, clean_versions)
            cves_dict = get_cves_dict([self.ga + '|' + v for v in vul_versions])
            unreachable_versions, reachable_versions = depGraph.exclude_reachable_vulnerable_versions(self.ga, cves_dict, c)
            # look for non-vul (QM)
            candidates = get_unreachable_fewest_vul_vers(self.gav, c, unreachable_versions)
        else:
            candidates = clean_versions




        # look for least dep nodes (QM)
        candidates = get_least_deps_introducing_versions(c, self.gav, candidates)[0]


        # look for no dependency conflict (BP)
        if len(candidates) == 0:
            candidates = depGraph.exclude_reachable_incomaptible_versions(c, self.gav, clean_versions)


        # if pre-filtered versions have API breaking, then check API breaking first then post-filter
        if len(candidates) == 0:
            candidates = depGraph.exclude_reachable_incomaptible_versions(c, self.gav, self.get_all_versions(c))
            non_breaking_candidates = candidates
            candidates = get_unreachable_fewest_vul_vers(self.gav, c, candidates)
            non_breaking_vul_candidates = candidates
            # look for minor and patch (QM)
            candidates = get_non_major_vers(c, self.gav, candidates)
            # look for non-dev (QM)
            candidates = get_non_dev_vers(candidates, self.original_version)
            # look for least dep nodes (QM)
            candidates = get_least_deps_introducing_versions(c, self.gav, candidates)[0]
            # If all versions have breaking, then relax secondary objectives
            if len(candidates) == 0:
                # relax major/dev limits
                if len(non_breaking_vul_candidates) != 0:
                    self.set_candidates(non_breaking_vul_candidates)
                # backtrack because all constraints broken
                else:
                    # if non compatible, hard backtrack
                    if len(non_breaking_candidates) == 0:
                        return 'hard'
                    if len(non_breaking_vul_candidates) == 0:
                        return 'soft'
                # low_candidates_list = depGraph.get_unreachable_vulnerable_versions_by_prioritization(self.ga, c,
                #                                                                                  clean_versions=clean_versions)
                # self.set_low_candidates(low_candidates_list[0])
                # self.set_candidates(low_candidates_list[0])
            else:
                self.set_candidates(candidates)
        else:
            self.set_candidates(candidates)

        return False

    def set_default_version(self, c, depGraph):
        # Skip the calculated and non-backtrack
        if self.preferred!='' and self.is_backtrack==False:
            return

        # remove backtrack invalid versions from candidates
        for incom_ver in self.get_hard_incom_vers():
            self.candidates.remove(incom_ver)

        # # if this is backtracked parent, handle it specially
        # if self.is_backtrack == 'hard':

        # if original is in candidates, stay same
        if self.get_original_version() in self.candidates:
            self.preferred = self.get_original_version()
            return

        if len(self.candidates) == 1:
            self.preferred = self.candidates[0]
            return
        from mip_library.script import distance_smt
        # if this node is direct dep
        if self.lvl==1:
            if self.original_version in self.candidates:
                self.preferred = self.original_version
                return
            else:
                tmp = [e for e in self.candidates]
                tmp.append(self.original_version)
                tmp = _sort(tmp)
                if tmp.index(self.original_version)==len(tmp)-1:
                    self.preferred = self.candidates[-1]
                else:
                    self.preferred = tmp[tmp.index(self.original_version)+1]
                return
        maven_deps = c['library-crawler']['maven_deps']

        smallest_nodes = self.__get_highest_parents()
        # if smallest_lvl node = 1, set as the default one
        if len(smallest_nodes) == 1:
            default_version = get_closest_default(smallest_nodes[0], self.ga, self.candidates, c)
            self.preferred = default_version
            return

        # if smallest_lvl node > 1, set as the center of default versions
        if len(smallest_nodes)>1:
            # If higher lvl >1 then pick the average of defaults
            if smallest_nodes[0].get_lvl()-self.lvl<-1 or smallest_nodes[0].get_lvl()-self.lvl>=1:
                self.preferred = get_averaged_defaults(smallest_nodes, self.ga, self.original_version, self.candidates, c)
                return
            # If higher lvl =1 then run SMT for all connected
            if smallest_nodes[0].get_lvl()-self.lvl<=0:
                # Find all connected, exclude highest parents whose lvl gap>1
                edges = []
                for parent in smallest_nodes:
                    edges.append([parent, self])
                next = smallest_nodes
                while len(next)>0:
                    tmp = [each for each in next]
                    next = []
                    for each_parent in tmp:
                        each_parent.calculate_candidates_safer(c, depGraph)
                        for son in filter(lambda x: x.get_lvl() == self.lvl and x.get_ga()!=self.ga, each_parent.get_sons()):

                            backtrack = son.calculate_candidates_safer(c, depGraph)
                            if backtrack == 'hard':
                                parents = son.get_parents()
                                parents = Node.sort_by_lvl(parents, reverse=True)
                                target_parent = parents[-1][0]
                                target_parent.set_backtrack(True)
                                target_parent.get_hard_incom_vers().add(target_parent.get_preferred())
                                return target_parent
                            edges.append([each_parent, son])
                            # additional_parents = son.__get_highest_parents()
                            # additional_parents = filter(lambda x: x.get_lvl()==self.lvl+1, additional_parents)
                            # next.extend(additional_parents)
                            # for additional_parent in additional_parents:
                            #     backtrack = additional_parent.calculate_candidates_safer(c, depGraph)
                            #     if backtrack == 'hard':
                            #         parents = additional_parent.get_parents()
                            #         parents = Node.sort_by_lvl(parents, reverse=True)
                            #         target_parent = parents[-1]
                            #         target_parent.set_backtrack(True)
                            #         target_parent.get_hard_incom_vers().add(target_parent.get_preferred())
                            #         return target_parent
                # run smt to set preferred version for all counted
                try:
                    distance_smt(edges, c, depGraph)
                except Exception as e:
                    # raise NoSolutionFound('SMT failed')
                    self.preferred = get_averaged_defaults(smallest_nodes, self.ga, self.original_version,
                                                           self.candidates, c)

        return None

    def reset_lvl(self):
        if len(self.parents)==0:
            # self.set_lvl(-1)
            return
        parents = self.__get_highest_parents()
        if len(parents)==0:
            return
        else:
            lvl = parents[0].get_lvl()
            self.set_lvl(lvl+1)

    def check_central(self, c):
        g, a, v = self.gav.split('|')
        if c is not None:
            try:
                maven = c['library-crawler']['maven']
                docs = maven.find_one({'group': g, 'artifact': a})
                if docs:
                    return True
            except Exception:
                pass
        try:
            from utils.deps_dev_api import is_in_central_deps_dev
            return is_in_central_deps_dev(g, a)
        except Exception:
            return True

    def check_parents_lvls(self, visited):
        # if backtrack, then normal
        if self.is_backtrack:
            return True

        # If all parents already visited
        x = lambda a: a.get_ga() in visited
        if len(list(filter(x, self.get_parents()))) == len(self.get_parents()):
            return True
        # If all parents are not set preferred
        x = lambda a: a.get_preferred()==None
        if len(list(filter(x, self.get_parents()))) == len(self.get_parents()):
            return False
        if len(self.get_parents())==1:
            return True
        smalls = self.__get_highest_parents()
        # normal = False
        # for small in smalls:
        #     if small.get_lvl()<=self.get_lvl():
        #         normal = True
        #         return normal
        # return normal
        return True

    @staticmethod
    def sort_by_lvl(nodes, reverse=False):
        d = defaultdict(list)
        for n in nodes:
            d[n.get_lvl()].append(n)
        lvls = list(d.keys())
        lvls.sort(reverse=reverse)
        return [d[l] for l in lvls]


