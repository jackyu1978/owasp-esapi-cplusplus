Start by fetching the latest stable boost from svn. The TAR/ZIP archives do not include Boost's tools, so you have to go to SVN.

    $ svn co http://svn.boost.org/svn/boost/tags/release/Boost_1_54_0/ boost-1.54.0

Then, build bcp, which allows one to copy out a class with its dependencies:

    $ cd boost-1.54.0
    $ ./bootstrap.sh
    $ cd tools/bcp
    $ ../../bjam

Finally, copy out shared_ptr:

    $ mkdir boost-stuff
    $ cd boost-1.54.0
    $ ./dist/bin/bcp shared_ptr unordered_map ../boost-stuff
