"" shell32's vim/nvim configuration
"" original: https://codeberg.org/s3gfa0lt/puppet/raw/branch/main/home/features/cli/nvim/vimrc

"" Options
" General
set mouse="!"
set magic
set hidden
set notimeout
set autoindent
set smartindent
set encoding=utf-8
set clipboard=unnamedplus

" File
set autoread
set noswapfile
set undofile

" Ui
set number
set relativenumber
set nowrap
set lazyredraw
set cc=80

" Mapping
let mapleader="\<space>"
nnoremap <Esc> :noh<cr>
