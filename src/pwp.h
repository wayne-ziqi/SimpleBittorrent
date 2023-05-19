//
// Created by ziqi on 2023/5/18.
//

#ifndef SIMPLETORRENT_PWP_H
#define SIMPLETORRENT_PWP_H

#include "util.h"

/**
 * some peers want to download from me, so I need to listen to them, this thread
 * upload downloaded pieces to interested peers
 */
void* upload_for_peers(void *arg);

/**
 * some peers want to upload to me, so I need to connect to them, this thread
 * download pieces from interested peers
 */
void* download_from_peers(void *arg);

#endif //SIMPLETORRENT_PWP_H
